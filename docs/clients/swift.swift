// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//
// Install: SwiftOTP (SPM).
// Env: AUTH_TOTP_SECRET (base32), JWT_SERVICE_URL (default http://localhost:8080).
// See README.md for endpoints, error codes and client rules.

import Foundation
import SwiftOTP

/// Reply of an issue or refresh call.
struct TokenResponse: Decodable {
    /// Signed JWT: `header.payload.signature`.
    let token: String
    /// Present only when a refresh token was requested.
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case token
        case refreshToken = "refresh_token"
    }
}

/// Reply of a bulk revoke call.
struct RevokeGroupResponse: Decodable {
    /// Number of revoked tokens.
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
struct JwtServiceClient {

    /// Sent as the Host header, becomes the `iss` claim.
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

    /// Fresh TOTP code, computed right before each call.
    private func totpCode() throws -> String {
        guard let code = totp.generate(time: Date()) else { throw ClientError.totpFailed }
        return code
    }

    /// Sends a level 3 request with a fresh code.
    ///
    /// - Parameters:
    ///   - method: HTTP method.
    ///   - path: endpoint path.
    ///   - body: request body, or `nil`.
    /// - Returns: response body and HTTP status.
    private func request(
        _ method: String,
        _ path: String,
        body: [String: Any]? = nil
    ) async throws -> (Data, Int) {
        var request = URLRequest(url: URL(string: baseURL + path)!)
        request.httpMethod = method

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

    /// `POST /tokens`
    ///
    /// - Parameters:
    ///   - sub: subject.
    ///   - aud: audience.
    ///   - withRefresh: also ask for a refresh token.
    ///   - claims: custom claims.
    /// - Returns: the issued token and, if requested, a refresh token.
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

    /// `POST /tokens/refresh` — returns a new pair; the old refresh token is
    /// dead once the call succeeds.
    ///
    /// - Parameter refreshToken: token from an issue or a previous refresh.
    /// - Returns: the new access + refresh pair.
    func refreshTokens(_ refreshToken: String) async throws -> TokenResponse {
        let (data, status) = try await request(
            "POST", "/tokens/refresh",
            body: ["refresh_token": refreshToken]
        )

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    /// `DELETE /tokens/{jti}` — idempotent.
    ///
    /// - Parameter jti: token id from the `jti` claim.
    func revokeToken(_ jti: String) async throws {
        let (_, status) = try await request("DELETE", "/tokens/\(jti)")
        guard status == 204 else { throw ClientError.unexpectedStatus(status) }
    }

    /// `DELETE /subjects/{sub}/tokens`
    ///
    /// - Parameter sub: subject whose tokens are revoked.
    /// - Returns: number of revoked tokens.
    func revokeSubject(_ sub: String) async throws -> Int {
        let (data, status) = try await request("DELETE", "/subjects/\(sub)/tokens")

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(RevokeGroupResponse.self, from: data).revoked
    }
}

// Issue -> refresh -> revoke.
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
