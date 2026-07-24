# Julia — библиотеки: SHA + HTTP (`import Pkg; Pkg.add(["HTTP"])`)
# AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (для base32 используйте пакет Base32).
using SHA, HTTP

secret  = Vector{UInt8}(ENV["AUTH_TOTP_SECRET"])
service = get(ENV, "JWT_SERVICE_URL", "http://localhost:8080")

counter = UInt64(floor(time() / 30))
msg = reinterpret(UInt8, [hton(counter)])
hs = hmac_sha1(secret, collect(msg))
off = (hs[end] & 0x0f) + 1
bin = (UInt32(hs[off] & 0x7f) << 24) | (UInt32(hs[off+1]) << 16) |
      (UInt32(hs[off+2]) << 8) | UInt32(hs[off+3])
code = lpad(string(bin % 1000000), 6, '0')

resp = HTTP.post("$service/tokens",
    ["X-TOTP-Code" => code, "Host" => "example.com", "Content-Type" => "application/json"],
    """{"sub":"svc-a","aud":["svc-b"]}"""; status_exception = false)
println(resp.status)
