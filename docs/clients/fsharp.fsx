/// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
///
/// TOTP is computed with .NET HMACSHA1, no external packages needed.
///
/// Environment:
/// - `AUTH_TOTP_SECRET` — shared TOTP secret (see the base32 note below);
/// - `JWT_SERVICE_URL` — base URL, default `http://localhost:8080`.
///
/// This example treats the secret as raw UTF-8 bytes; add a base32 decoder for
/// Google Authenticator compatibility.
///
/// **The code is recomputed before every request.** With replay protection on
/// (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already seen
/// with `401`, even while that code is still inside its time window.
module JwtServiceClient

open System
open System.Net.Http
open System.Security.Cryptography
open System.Text
open System.Text.Json

/// Sent as the Host header and becomes the `iss` claim. Must be the same on
/// issue and on verify, or the token will not verify.
let issuerHost = "example.com"

/// Service base URL from the environment.
let serviceUrl =
    match Environment.GetEnvironmentVariable "JWT_SERVICE_URL" with
    | null | "" -> "http://localhost:8080"
    | value -> value

let private http = new HttpClient()

/// Computes a fresh TOTP code for right now.
///
/// Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
/// RFC 4226 section 5.3.
///
/// Returns six decimal digits.
let totpCode () : string =
    let secret = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable "AUTH_TOTP_SECRET")
    let counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30L

    let message = BitConverter.GetBytes counter
    if BitConverter.IsLittleEndian then Array.Reverse message

    use hmac = new HMACSHA1(secret)
    let digest = hmac.ComputeHash message

    let offset = int (digest.[digest.Length - 1] &&& 0x0fuy)
    let code =
        ((int digest.[offset] &&& 0x7f) <<< 24)
        ||| (int digest.[offset + 1] <<< 16)
        ||| (int digest.[offset + 2] <<< 8)
        ||| int digest.[offset + 3]

    sprintf "%06d" (code % 1000000)

/// Sends a level 3 request.
///
/// `method` is the HTTP method, `path` the endpoint path, `body` the request
/// body or `None`.
///
/// Returns the HTTP status and the response body.
let request (method: HttpMethod) (path: string) (body: string option) : int * string =
    use message = new HttpRequestMessage(method, serviceUrl + path)

    // Computed here rather than reused: one code, one request.
    message.Headers.Add("X-TOTP-Code", totpCode ())
    message.Headers.Host <- issuerHost

    body
    |> Option.iter (fun content ->
        message.Content <- new StringContent(content, Encoding.UTF8, "application/json"))

    let response = http.Send message
    let text = response.Content.ReadAsStringAsync().Result

    int response.StatusCode, text

/// Issues an access token (`POST /tokens`).
///
/// `sub` is the subject (`sub` claim), `aud` the audience (`aud` claim),
/// `withRefresh` also returns a refresh token for extending the session, and
/// `claimsJson` carries custom claims as a JSON object (for example
/// `{"role":"admin"}`) or `None`.
///
/// Custom claims sit next to the registered ones, so the consumer reads `role`,
/// not `extra.role`. Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
/// `jti`) give `422` — change lifetime through `ttl`, not `exp`.
///
/// Errors: `401` bad code, `422` bad parameters or forbidden claim, `500` JWKS
/// or Redis unavailable.
let issueToken (sub: string) (aud: string) (withRefresh: bool) (claimsJson: string option) : string =
    let claimsPart =
        claimsJson |> Option.map (sprintf ",\"claims\":%s") |> Option.defaultValue ""

    let body =
        sprintf """{"sub":"%s","aud":["%s"],"refresh":%b%s}""" sub aud withRefresh claimsPart

    match request HttpMethod.Post "/tokens" (Some body) with
    | 200, text -> text
    | status, _ -> failwithf "issue failed: %d" status

/// Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
///
/// The old token dies on exchange: store the new one and drop the previous.
///
/// **Never retry** an exchange with the old token when the reply is lost. A
/// second presentation reads as theft, and the server revokes the whole family —
/// refresh tokens and the access tokens issued from them. Issue a new pair
/// instead.
///
/// `401` means the token is unknown, expired or already used.
let refreshTokens (refreshToken: string) : string =
    let body = sprintf """{"refresh_token":"%s"}""" refreshToken

    match request HttpMethod.Post "/tokens/refresh" (Some body) with
    | 200, text -> text
    | status, _ -> failwithf "refresh failed: %d" status

/// Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
///
/// Idempotent: revoking an unknown `jti` is success too. `500` means the store
/// is unreachable and the token is **not** revoked: retry.
let revokeToken (jti: string) : unit =
    match request HttpMethod.Delete (sprintf "/tokens/%s" jti) None with
    | 204, _ -> ()
    | status, _ -> failwithf "revoke failed: %d" status

/// Revokes every active token of a subject.
///
/// Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens cannot
/// be killed one by one because the caller does not know their `jti`.
///
/// Returns the number of revoked tokens; expired ones do not count.
let revokeSubject (sub: string) : int =
    match request HttpMethod.Delete (sprintf "/subjects/%s/tokens" sub) None with
    | 200, text ->
        use document = JsonDocument.Parse text
        document.RootElement.GetProperty("revoked").GetInt32()
    | status, _ -> failwithf "bulk revoke failed: %d" status

// Full token lifecycle: issue, refresh, bulk revoke.
let issued = issueToken "svc-a" "svc-b" true (Some """{"role":"admin"}""")
printfn "issued: %s" issued

// Real code should parse the JSON and take refresh_token from it.
use issuedDocument = JsonDocument.Parse issued
let refreshToken = issuedDocument.RootElement.GetProperty("refresh_token").GetString()

printfn "refreshed: %s" (refreshTokens refreshToken)
printfn "revoked: %d" (revokeSubject "svc-a")
