"""
jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

Dependencies: `using Pkg; Pkg.add(["HTTP", "JSON3"])` (SHA ships with stdlib).

# Environment
- `AUTH_TOTP_SECRET` — shared TOTP secret (see the base32 note below);
- `JWT_SERVICE_URL` — base URL, default `http://localhost:8080`.

This example treats the secret as raw bytes; add a base32 decoder for Google
Authenticator compatibility.

!!! warning "One code, one request"
    The code is recomputed before every request. With replay protection on
    (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already
    seen with 401, even while that code is still inside its time window.
"""
module JwtServiceClient

using HTTP
using JSON3
using SHA

"""Sent as the Host header and becomes the `iss` claim. Must be the same on
issue and on verify, or the token will not verify."""
const ISSUER_HOST = "example.com"

"""
    service_url() -> String

Service base URL from the environment.
"""
service_url() = get(ENV, "JWT_SERVICE_URL", "http://localhost:8080")

"""
    totp_code() -> String

Computes a fresh TOTP code for right now.

Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows RFC 4226
section 5.3.

Returns six decimal digits.
"""
function totp_code()
    secret = Vector{UInt8}(ENV["AUTH_TOTP_SECRET"])
    counter = UInt64(floor(time() / 30))
    message = reinterpret(UInt8, [hton(counter)])

    digest = hmac_sha1(secret, collect(message))
    offset = (digest[end] & 0x0f) + 1

    code = (UInt32(digest[offset] & 0x7f) << 24) |
           (UInt32(digest[offset + 1]) << 16) |
           (UInt32(digest[offset + 2]) << 8) |
           UInt32(digest[offset + 3])

    return lpad(code % 1000000, 6, '0')
end

"""
    request(method, path; body=nothing) -> HTTP.Response

Sends a level 3 request.

# Arguments
- `method`: HTTP method.
- `path`: endpoint path.
- `body`: request body, or `nothing` when there is none.
"""
function request(method, path; body = nothing)
    headers = [
        # Computed here rather than reused: one code, one request.
        "X-TOTP-Code" => totp_code(),
        "Host" => ISSUER_HOST,
        "Content-Type" => "application/json",
    ]

    payload = body === nothing ? "" : JSON3.write(body)
    return HTTP.request(method, service_url() * path, headers, payload; status_exception = false)
end

"""
    issue_token(sub, aud; with_refresh=false, claims=Dict()) -> Dict

Issues an access token (`POST /tokens`).

# Arguments
- `sub`: subject the token is issued to (`sub` claim).
- `aud`: audience (`aud` claim); must not be empty.
- `with_refresh`: also return a refresh token for extending the session.
- `claims`: custom claims (role, scope, tenant) — they sit next to the
  registered ones, so the consumer reads `role`, not `extra.role`. Reserved
  names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) give 422 — change
  lifetime through `ttl`, not `exp`.

Errors on 401 (bad code), 422 (bad parameters or forbidden claim) and 500 (JWKS
or Redis unavailable).
"""
function issue_token(sub, aud; with_refresh = false, claims = Dict())
    body = Dict("sub" => sub, "aud" => aud, "refresh" => with_refresh)
    isempty(claims) || (body["claims"] = claims)

    response = request("POST", "/tokens"; body = body)
    response.status == 200 || error("issue failed: $(response.status)")

    return JSON3.read(String(response.body), Dict)
end

"""
    refresh_tokens(refresh_token) -> Dict

Exchanges a refresh token for a new pair (`POST /tokens/refresh`).

The old token dies on exchange: store the new one and drop the previous.

!!! danger "Never retry the exchange"
    When the reply is lost, do not repeat the exchange with the old token. A
    second presentation reads as theft, and the server revokes the whole family
    — refresh tokens and the access tokens issued from them. Issue a new pair
    instead.
"""
function refresh_tokens(refresh_token)
    response = request("POST", "/tokens/refresh"; body = (refresh_token = refresh_token,))
    response.status == 200 || error("refresh failed: $(response.status)")

    return JSON3.read(String(response.body), Dict)
end

"""
    revoke_token(jti)

Revokes one token by its `jti` (`DELETE /tokens/{jti}`).

Idempotent: revoking an unknown `jti` is success too. An error means the store
is unreachable and the token is **not** revoked: retry.
"""
function revoke_token(jti)
    response = request("DELETE", "/tokens/$jti")
    response.status == 204 || error("revoke failed: $(response.status)")

    return nothing
end

"""
    revoke_subject(sub) -> Int

Revokes every active token of a subject (`DELETE /subjects/{sub}/tokens`).

The compromise path: tokens cannot be killed one by one because the caller does
not know their `jti`. Returns the number of revoked tokens; expired ones do not
count.
"""
function revoke_subject(sub)
    response = request("DELETE", "/subjects/$sub/tokens")
    response.status == 200 || error("bulk revoke failed: $(response.status)")

    return JSON3.read(String(response.body), Dict)["revoked"]
end

end # module

# Full token lifecycle: issue, refresh, bulk revoke.
using .JwtServiceClient

issued = JwtServiceClient.issue_token("svc-a", ["svc-b"]; with_refresh = true,
                                      claims = Dict("role" => "admin"))
println("issued: ", first(issued["token"], 32), "...")

refreshed = JwtServiceClient.refresh_tokens(issued["refresh_token"])
println("refreshed: ", first(refreshed["token"], 32), "...")

println("revoked: ", JwtServiceClient.revoke_subject("svc-a"))
