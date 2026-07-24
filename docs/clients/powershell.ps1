# PowerShell — TOTP через HMACSHA1 (.NET) + Invoke-WebRequest.
# AUTH_TOTP_SECRET здесь ожидается как СЫРЫЕ байты (UTF-8). Для base32 добавьте декодер.
$secret  = [Text.Encoding]::UTF8.GetBytes($env:AUTH_TOTP_SECRET)
$service = if ($env:JWT_SERVICE_URL) { $env:JWT_SERVICE_URL } else { 'http://localhost:8080' }

$counter = [long][Math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) / 30)
$msg = [BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder($counter))
$hmac = [Security.Cryptography.HMACSHA1]::new($secret)
$hs = $hmac.ComputeHash($msg)
$off = $hs[$hs.Length - 1] -band 0x0f
$bin = (($hs[$off] -band 0x7f) -shl 24) -bor ($hs[$off+1] -shl 16) -bor ($hs[$off+2] -shl 8) -bor $hs[$off+3]
$code = '{0:D6}' -f ($bin % 1000000)

$resp = Invoke-WebRequest -Uri "$service/tokens" -Method Post `
  -Headers @{ 'X-TOTP-Code' = $code; 'Host' = 'example.com' } `
  -ContentType 'application/json' -Body '{"sub":"svc-a","aud":["svc-b"]}' -SkipHttpErrorCheck
$resp.StatusCode
