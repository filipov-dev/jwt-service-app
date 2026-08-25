/// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
///
/// TOTP is computed with .NET HMACSHA1, no external packages needed.
///
/// Env: `AUTH_TOTP_SECRET` (raw UTF-8 bytes here, see README.md),
/// `JWT_SERVICE_URL` (default `http://localhost:8080`).
///
/// See README.md for endpoints, error codes and client rules.
module JwtServiceClient

open System
open System.Net.Http
open System.Security.Cryptography
open System.Text
open System.Text.Json

/// Sent as the Host header, becomes the `iss` claim.
let issuerHost = "example.com"

/// Service base URL from the environment.
let serviceUrl =
    match Environment.GetEnvironmentVariable "JWT_SERVICE_URL" with
    | null | "" -> "http://localhost:8080"
    | value -> value

let private http = new HttpClient()

/// Fresh TOTP code: SHA-1, 6 digits, 30-second step.
///
/// Truncation follows RFC 4226 section 5.3.
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

/// Sends a level 3 request with a code computed right before the call.
///
/// Returns the HTTP status and the response body.
let request (method: HttpMethod) (path: string) (body: string option) : int * string =
    use message = new HttpRequestMessage(method, serviceUrl + path)

    message.Headers.Add("X-TOTP-Code", totpCode ())
    message.Headers.Host <- issuerHost

    body
    |> Option.iter (fun content ->
        message.Content <- new StringContent(content, Encoding.UTF8, "application/json"))

    let response = http.Send message
    let text = response.Content.ReadAsStringAsync().Result

    int response.StatusCode, text

/// `POST /tokens`
///
/// `claimsJson` carries custom claims as a JSON object, or `None`.
let issueToken (sub: string) (aud: string) (withRefresh: bool) (claimsJson: string option) : string =
    let claimsPart =
        claimsJson |> Option.map (sprintf ",\"claims\":%s") |> Option.defaultValue ""

    let body =
        sprintf """{"sub":"%s","aud":["%s"],"refresh":%b%s}""" sub aud withRefresh claimsPart

    match request HttpMethod.Post "/tokens" (Some body) with
    | 200, text -> text
    | status, _ -> failwithf "issue failed: %d" status

/// `POST /tokens/refresh` — returns a new pair; the old refresh token is dead
/// once the call succeeds.
let refreshTokens (refreshToken: string) : string =
    let body = sprintf """{"refresh_token":"%s"}""" refreshToken

    match request HttpMethod.Post "/tokens/refresh" (Some body) with
    | 200, text -> text
    | status, _ -> failwithf "refresh failed: %d" status

/// `DELETE /tokens/{jti}` — idempotent.
let revokeToken (jti: string) : unit =
    match request HttpMethod.Delete (sprintf "/tokens/%s" jti) None with
    | 204, _ -> ()
    | status, _ -> failwithf "revoke failed: %d" status

/// `DELETE /subjects/{sub}/tokens` — returns the number of revoked tokens.
let revokeSubject (sub: string) : int =
    match request HttpMethod.Delete (sprintf "/subjects/%s/tokens" sub) None with
    | 200, text ->
        use document = JsonDocument.Parse text
        document.RootElement.GetProperty("revoked").GetInt32()
    | status, _ -> failwithf "bulk revoke failed: %d" status

// Issue -> refresh -> revoke.
let issued = issueToken "svc-a" "svc-b" true (Some """{"role":"admin"}""")
printfn "issued: %s" issued

// Real code should parse the JSON and take refresh_token from it.
use issuedDocument = JsonDocument.Parse issued
let refreshToken = issuedDocument.RootElement.GetProperty("refresh_token").GetString()

printfn "refreshed: %s" (refreshTokens refreshToken)
printfn "revoked: %d" (revokeSubject "svc-a")
