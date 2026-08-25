--- jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
--
-- Dependencies: `luaossl` (HMAC), `lua-http` (HTTP), `dkjson` (JSON).
--
-- Environment:
--
-- * `AUTH_TOTP_SECRET` — shared TOTP secret (see the base32 note below);
-- * `JWT_SERVICE_URL` — base URL, default `http://localhost:8080`.
--
-- This example treats the secret as raw bytes; add a base32 decoder for Google
-- Authenticator compatibility.
--
-- **The code is recomputed before every request.** With replay protection on
-- (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already seen
-- with 401, even while that code is still inside its time window.
--
-- @module jwt_service_client
-- @license MIT

local hmac = require 'openssl.hmac'
local json = require 'dkjson'
local request = require 'http.request'

local M = {}

--- Sent as the Host header and becomes the `iss` claim. Must be the same on
-- issue and on verify, or the token will not verify.
-- @field ISSUER_HOST
M.ISSUER_HOST = 'example.com'

--- Returns the service base URL from the environment.
-- @treturn string Service URL.
local function service_url()
  return os.getenv('JWT_SERVICE_URL') or 'http://localhost:8080'
end

--- Computes a fresh TOTP code for right now.
--
-- Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
-- RFC 4226 section 5.3.
--
-- @treturn string Six decimal digits.
function M.totp_code()
  local secret = os.getenv('AUTH_TOTP_SECRET')
  local counter = math.floor(os.time() / 30)

  -- Counter as 8 big-endian bytes.
  local message = ''
  for i = 7, 0, -1 do
    message = message .. string.char(math.floor(counter / 2 ^ (8 * i)) % 256)
  end

  local digest = hmac.new(secret, 'sha1'):final(message)
  local offset = (digest:byte(#digest) % 16) + 1

  local code = ((digest:byte(offset) % 128) * 2 ^ 24)
    + (digest:byte(offset + 1) * 2 ^ 16)
    + (digest:byte(offset + 2) * 2 ^ 8)
    + digest:byte(offset + 3)

  return string.format('%06d', code % 1000000)
end

--- Sends a level 3 request.
--
-- @tparam string method HTTP method.
-- @tparam string path Endpoint path.
-- @tparam ?table body Request body, or nil when there is none.
-- @treturn number HTTP status.
-- @treturn string Response body.
local function do_request(method, path, body)
  local req = request.new_from_uri(service_url() .. path)
  req.headers:upsert(':method', method)

  -- Computed here rather than reused: one code, one request.
  req.headers:upsert('x-totp-code', M.totp_code())
  req.headers:upsert('host', M.ISSUER_HOST)
  req.headers:upsert('content-type', 'application/json')

  if body then
    req:set_body(json.encode(body))
  end

  local headers, stream = req:go()
  return tonumber(headers:get(':status')), stream:get_body_as_string()
end

--- Issues an access token (`POST /tokens`).
--
-- @tparam string sub Subject the token is issued to (`sub` claim).
-- @tparam table aud Audience (`aud` claim); must not be empty.
-- @tparam ?boolean with_refresh Also return a refresh token for extending the
--   session.
-- @tparam ?table claims Custom claims (role, scope, tenant) — they sit next to
--   the registered ones, so the consumer reads `role`, not `extra.role`.
--   Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) give 422 —
--   change lifetime through `ttl`, not `exp`.
-- @treturn table Reply with `token` and, if requested, `refresh_token`.
-- @raise Error on 401 (bad code), 422 (bad parameters or forbidden claim),
--   500 (JWKS or Redis unavailable).
function M.issue_token(sub, aud, with_refresh, claims)
  local payload = {
    sub = sub,
    aud = aud,
    refresh = with_refresh or false,
  }
  if claims and next(claims) then
    payload.claims = claims
  end

  local status, body = do_request('POST', '/tokens', payload)

  assert(status == 200, 'issue failed: ' .. status)
  return json.decode(body)
end

--- Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
--
-- The old token dies on exchange: store the new one and drop the previous.
--
-- **Never retry** an exchange with the old token when the reply is lost. A
-- second presentation reads as theft, and the server revokes the whole family —
-- refresh tokens and the access tokens issued from them. Issue a new pair
-- instead.
--
-- @tparam string refresh_token Token from an issue or a previous exchange.
-- @treturn table New `token` and `refresh_token`.
-- @raise Error on 401 — token unknown, expired or already used.
function M.refresh_tokens(refresh_token)
  local status, body = do_request('POST', '/tokens/refresh', {
    refresh_token = refresh_token,
  })

  assert(status == 200, 'refresh failed: ' .. status)
  return json.decode(body)
end

--- Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
--
-- Idempotent: revoking an unknown `jti` is success too.
--
-- @tparam string jti Token id from the `jti` claim.
-- @raise Error on 500 — store unreachable, the token is NOT revoked; retry.
function M.revoke_token(jti)
  local status = do_request('DELETE', '/tokens/' .. jti, nil)
  assert(status == 204, 'revoke failed: ' .. status)
end

--- Revokes every active token of a subject.
--
-- Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens cannot
-- be killed one by one because the caller does not know their `jti`.
--
-- @tparam string sub Subject whose tokens are killed.
-- @treturn number Number of revoked tokens; expired ones do not count.
function M.revoke_subject(sub)
  local status, body = do_request('DELETE', '/subjects/' .. sub .. '/tokens', nil)

  assert(status == 200, 'bulk revoke failed: ' .. status)
  return json.decode(body).revoked
end

-- Full token lifecycle: issue, refresh, bulk revoke.
local issued = M.issue_token('svc-a', { 'svc-b' }, true, { role = 'admin' })
print('issued: ' .. issued.token:sub(1, 32) .. '...')

local refreshed = M.refresh_tokens(issued.refresh_token)
print('refreshed: ' .. refreshed.token:sub(1, 32) .. '...')

print('revoked: ' .. M.revoke_subject('svc-a'))

return M
