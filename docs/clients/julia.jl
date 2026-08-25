"""
jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

Install: `using Pkg; Pkg.add(["HTTP", "JSON3"])` (SHA ships with stdlib).

Env: `AUTH_TOTP_SECRET` (raw bytes here, see README.md), `JWT_SERVICE_URL`
(default `http://localhost:8080`).

See README.md for endpoints, error codes and client rules.
"""
module JwtServiceClient

using HTTP
using JSON3
using SHA

"""Sent as the Host header, becomes the `iss` claim."""
const ISSUER_HOST = "example.com"

"""
    service_url() -> String

Service base URL from the environment.
"""
service_url() = get(ENV, "JWT_SERVICE_URL", "http://localhost:8080")

"""
    totp_code() -> String

Fresh TOTP code: SHA-1, 6 digits, 30-second step. Truncation follows RFC 4226
section 5.3.
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

Sends a level 3 request with a code computed right before the call.

# Arguments
- `method`: HTTP method.
- `path`: endpoint path.
- `body`: request body, or `nothing`.
"""
function request(method, path; body = nothing)
    headers = [
        "X-TOTP-Code" => totp_code(),
        "Host" => ISSUER_HOST,
        "Content-Type" => "application/json",
    ]

    payload = body === nothing ? "" : JSON3.write(body)
    return HTTP.request(method, service_url() * path, headers, payload; status_exception = false)
end

"""
    issue_token(sub, aud; with_refresh=false, claims=Dict()) -> Dict

`POST /tokens`

# Arguments
- `sub`: subject.
- `aud`: audience.
- `with_refresh`: also ask for a refresh token.
- `claims`: custom claims.
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

`POST /tokens/refresh` — returns a new pair; the old refresh token is dead once
the call succeeds.
"""
function refresh_tokens(refresh_token)
    response = request("POST", "/tokens/refresh"; body = (refresh_token = refresh_token,))
    response.status == 200 || error("refresh failed: $(response.status)")

    return JSON3.read(String(response.body), Dict)
end

"""
    revoke_token(jti)

`DELETE /tokens/{jti}` — idempotent.
"""
function revoke_token(jti)
    response = request("DELETE", "/tokens/$jti")
    response.status == 204 || error("revoke failed: $(response.status)")

    return nothing
end

"""
    revoke_subject(sub) -> Int

`DELETE /subjects/{sub}/tokens` — returns the number of revoked tokens.
"""
function revoke_subject(sub)
    response = request("DELETE", "/subjects/$sub/tokens")
    response.status == 200 || error("bulk revoke failed: $(response.status)")

    return JSON3.read(String(response.body), Dict)["revoked"]
end

end # module

# Issue -> refresh -> revoke.
using .JwtServiceClient

issued = JwtServiceClient.issue_token("svc-a", ["svc-b"]; with_refresh = true,
                                      claims = Dict("role" => "admin"))
println("issued: ", first(issued["token"], 32), "...")

refreshed = JwtServiceClient.refresh_tokens(issued["refresh_token"])
println("refreshed: ", first(refreshed["token"], 32), "...")

println("revoked: ", JwtServiceClient.revoke_subject("svc-a"))
