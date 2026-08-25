// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//
// Install: SwiftOTP (SPM).
//
// Env:
//   AUTH_TOTP_SECRET — shared TOTP secret, base32 (required);
//   JWT_SERVICE_URL  — service base URL, default http://localhost:8080.

import Foundation
import SwiftOTP

/// Reply of an issue or a refresh call.
struct TokenResponse: Decodable {
    /// Signed JWT: `header.payload.signature`.
    let token: String
    /// Refresh token; present only if it was requested.
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case token
        case refreshToken = "refresh_token"
    }
}

/// Reply of a bulk revoke call.
struct RevokeGroupResponse: Decodable {
    /// How many active tokens were revoked; expired ones do not count.
    let revoked: Int
}

/// Client errors.
enum ClientError: Error {
    /// The service replied with an unexpected status.
    case unexpectedStatus(Int)
    /// The TOTP code could not be computed.
    case totpFailed
}

/// Client of the token service, covering all four level 3 endpoints.
///
/// - Important: the code is recomputed **before every request**. With replay
///   protection on (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it
///   has already seen with `401`, even while that code is still inside its time
///   window.
struct JwtServiceClient {

    /// Sent as the Host header and becomes the `iss` claim. Must be the same on
    /// issue and on verify, or the token will not verify.
    private static let issuerHost = "example.com"

    private let baseURL: String
    private let totp: TOTP

    /// Creates a client.
    ///
    /// - Parameters:
    ///   - baseURL: service base URL.
    ///   - secret: shared TOTP secret, base32.
    init?(baseURL: String, secret: String) {
        guard let data = base32DecodeToData(secret),
              // Service defaults: SHA-1, 6 digits, 30-second step.
              let totp = TOTP(secret: data, digits: 6, timeInterval: 30, algorithm: .sha1)
        else { return nil }

        self.baseURL = baseURL
        self.totp = totp
    }

    /// Fresh code for right now.
    ///
    /// - Returns: six decimal digits.
    /// - Throws: ``ClientError/totpFailed`` if the generator fails.
    private func totpCode() throws -> String {
        guard let code = totp.generate(time: Date()) else { throw ClientError.totpFailed }
        return code
    }

    /// Sends a level 3 request.
    ///
    /// - Parameters:
    ///   - method: HTTP method.
    ///   - path: endpoint path.
    ///   - body: request body, or `nil` when there is none.
    /// - Returns: response body and HTTP status.
    private func request(
        _ method: String,
        _ path: String,
        body: [String: Any]? = nil
    ) async throws -> (Data, Int) {
        var request = URLRequest(url: URL(string: baseURL + path)!)
        request.httpMethod = method

        // Computed here rather than reused: one code, one request.
        request.setValue(try totpCode(), forHTTPHeaderField: "X-TOTP-Code")
        request.setValue(Self.issuerHost, forHTTPHeaderField: "Host")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0

        return (data, status)
    }

    /// Issues an access token (`POST /tokens`).
    ///
    /// - Parameters:
    ///   - sub: subject the token is issued to (`sub` claim).
    ///   - aud: audience (`aud` claim); must not be empty.
    ///   - withRefresh: also return a refresh token for extending the session.
    ///   - claims: custom claims (role, scope, tenant). They sit next to the
    ///     registered ones, so the consumer reads `role`, not `extra.role`.
    ///     Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) are
    ///     rejected with `422` — change lifetime through `ttl`, not `exp`.
    /// - Returns: the issued token and, if requested, a refresh token.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `401` bad code, `422`
    ///   bad parameters or forbidden claim, `500` JWKS or Redis unavailable.
    func issueToken(
        sub: String,
        aud: [String],
        withRefresh: Bool = false,
        claims: [String: Any] = [:]
    ) async throws -> TokenResponse {
        var body: [String: Any] = ["sub": sub, "aud": aud, "refresh": withRefresh]
        if !claims.isEmpty { body["claims"] = claims }

        let (data, status) = try await request("POST", "/tokens", body: body)

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    /// Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
    ///
    /// The old token dies on exchange: store the new one and drop the previous.
    ///
    /// - Warning: never retry an exchange with the old token when the reply is
    ///   lost. A second presentation reads as theft, and the server revokes the
    ///   whole family — refresh tokens and the access tokens issued from them.
    ///   Issue a new pair instead.
    ///
    /// - Parameter refreshToken: token from an issue or a previous exchange.
    /// - Returns: the new access + refresh pair.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `401` if the token is
    ///   unknown, expired or already used.
    func refreshTokens(_ refreshToken: String) async throws -> TokenResponse {
        let (data, status) = try await request(
            "POST", "/tokens/refresh",
            body: ["refresh_token": refreshToken]
        )

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    /// Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
    ///
    /// Idempotent: revoking an unknown `jti` is success too — the desired state
    /// holds either way.
    ///
    /// - Parameter jti: token id from the `jti` claim.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `500`, the store is
    ///   unreachable and the token is **not** revoked: retry.
    func revokeToken(_ jti: String) async throws {
        let (_, status) = try await request("DELETE", "/tokens/\(jti)")
        guard status == 204 else { throw ClientError.unexpectedStatus(status) }
    }

    /// Revokes every active token of a subject.
    ///
    /// Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens
    /// cannot be killed one by one because the caller does not know their `jti`.
    ///
    /// - Parameter sub: subject whose tokens are killed.
    /// - Returns: number of revoked tokens; expired ones do not count.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `500`, nothing was revoked.
    func revokeSubject(_ sub: String) async throws -> Int {
        let (data, status) = try await request("DELETE", "/subjects/\(sub)/tokens")

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(RevokeGroupResponse.self, from: data).revoked
    }
}

// Full token lifecycle: issue, refresh, bulk revoke.
let service = ProcessInfo.processInfo.environment["JWT_SERVICE_URL"] ?? "http://localhost:8080"
let secret = ProcessInfo.processInfo.environment["AUTH_TOTP_SECRET"]!

guard let client = JwtServiceClient(baseURL: service, secret: secret) else {
    fatalError("invalid AUTH_TOTP_SECRET")
}

let issued = try await client.issueToken(
    sub: "svc-a", aud: ["svc-b"], withRefresh: true, claims: ["role": "admin"])
print("issued:", issued.token.prefix(32), "...")

let refreshed = try await client.refreshTokens(issued.refreshToken!)
print("refreshed:", refreshed.token.prefix(32), "...")

print("revoked:", try await client.revokeSubject("svc-a"))
