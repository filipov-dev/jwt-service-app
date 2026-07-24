-- Lua — библиотека: openssl (luaossl / lua-openssl) + lua-http.
-- AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (для base32 добавьте декодер).
local openssl_hmac = require("openssl.hmac")
local request = require("http.request")

local secret  = os.getenv("AUTH_TOTP_SECRET")
local service = os.getenv("JWT_SERVICE_URL") or "http://localhost:8080"

local counter = math.floor(os.time() / 30)
local msg = ("")
for i = 7, 0, -1 do
  msg = msg .. string.char(math.floor(counter / (256 ^ i)) % 256)
end
local hs = openssl_hmac.new(secret, "sha1"):final(msg)
local off = (hs:byte(#hs) % 16) + 1
local bin = ((hs:byte(off) % 128) * 2^24) + (hs:byte(off+1) * 2^16)
          + (hs:byte(off+2) * 2^8) + hs:byte(off+3)
local code = string.format("%06d", bin % 1000000)

local req = request.new_from_uri(service .. "/tokens")
req.headers:upsert(":method", "POST")
req.headers:append("x-totp-code", code)
req.headers:upsert(":authority", "example.com")
req.headers:append("content-type", "application/json")
req:set_body('{"sub":"svc-a","aud":["svc-b"]}')
local headers = req:go()
print(headers:get(":status"))
