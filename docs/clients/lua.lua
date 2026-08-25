--- jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
--
-- Dependencies: `luaossl` (HMAC), `lua-http` (HTTP), `dkjson` (JSON).
--
-- Env: `AUTH_TOTP_SECRET` (raw bytes here, see README.md), `JWT_SERVICE_URL`
-- (default `http://localhost:8080`).
--
-- See README.md for endpoints, error codes and client rules.
--
-- @module jwt_service_client
-- @license MIT

local hmac = require 'openssl.hmac'
local json = require 'dkjson'
local request = require 'http.request'

local M = {}

--- Sent as the Host header, becomes the `iss` claim.
-- @field ISSUER_HOST
M.ISSUER_HOST = 'example.com'

--- Service base URL from the environment.
-- @treturn string Service URL.
local function service_url()
  return os.getenv('JWT_SERVICE_URL') or 'http://localhost:8080'
end

--- Fresh TOTP code: SHA-1, 6 digits, 30-second step.
--
-- Truncation follows RFC 4226 section 5.3.
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

--- Sends a level 3 request with a code computed right before the call.
--
-- @tparam string method HTTP method.
-- @tparam string path Endpoint path.
-- @tparam ?table body Request body, or nil.
-- @treturn number HTTP status.
-- @treturn string Response body.
local function do_request(method, path, body)
  local req = request.new_from_uri(service_url() .. path)
  req.headers:upsert(':method', method)

  req.headers:upsert('x-totp-code', M.totp_code())
  req.headers:upsert('host', M.ISSUER_HOST)
  req.headers:upsert('content-type', 'application/json')

  if body then
    req:set_body(json.encode(body))
  end

  local headers, stream = req:go()
  return tonumber(headers:get(':status')), stream:get_body_as_string()
end

--- `POST /tokens`
--
-- @tparam string sub Subject.
-- @tparam table aud Audience.
-- @tparam ?boolean with_refresh Also ask for a refresh token.
-- @tparam ?table claims Custom claims.
-- @treturn table Reply with `token` and, if requested, `refresh_token`.
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

--- `POST /tokens/refresh` — returns a new pair; the old refresh token is dead
--- once the call succeeds.
--
-- @tparam string refresh_token Token from an issue or a previous refresh.
-- @treturn table New `token` and `refresh_token`.
function M.refresh_tokens(refresh_token)
  local status, body = do_request('POST', '/tokens/refresh', {
    refresh_token = refresh_token,
  })

  assert(status == 200, 'refresh failed: ' .. status)
  return json.decode(body)
end

--- `DELETE /tokens/{jti}` — idempotent.
--
-- @tparam string jti Token id from the `jti` claim.
function M.revoke_token(jti)
  local status = do_request('DELETE', '/tokens/' .. jti, nil)
  assert(status == 204, 'revoke failed: ' .. status)
end

--- `DELETE /subjects/{sub}/tokens`
--
-- @tparam string sub Subject whose tokens are revoked.
-- @treturn number Number of revoked tokens.
function M.revoke_subject(sub)
  local status, body = do_request('DELETE', '/subjects/' .. sub .. '/tokens', nil)

  assert(status == 200, 'bulk revoke failed: ' .. status)
  return json.decode(body).revoked
end

-- Issue -> refresh -> revoke.
local issued = M.issue_token('svc-a', { 'svc-b' }, true, { role = 'admin' })
print('issued: ' .. issued.token:sub(1, 32) .. '...')

local refreshed = M.refresh_tokens(issued.refresh_token)
print('refreshed: ' .. refreshed.token:sub(1, 32) .. '...')

print('revoked: ' .. M.revoke_subject('svc-a'))

return M
