// F# — TOTP через HMACSHA1 (.NET) + HttpClient. Запуск: dotnet fsi totp.fsx
// AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (UTF-8). Для base32 добавьте декодер.
open System
open System.Net.Http
open System.Security.Cryptography
open System.Text

let secret = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable "AUTH_TOTP_SECRET")
let service =
    match Environment.GetEnvironmentVariable "JWT_SERVICE_URL" with
    | null | "" -> "http://localhost:8080"
    | s -> s

let counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30L
let msg = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder counter)
use hmac = new HMACSHA1(secret)
let hs = hmac.ComputeHash msg
let off = int (hs.[hs.Length - 1] &&& 0x0fuy)
let bin =
    ((int hs.[off] &&& 0x7f) <<< 24) ||| (int hs.[off+1] <<< 16)
    ||| (int hs.[off+2] <<< 8) ||| int hs.[off+3]
let code = sprintf "%06d" (bin % 1000000)

use client = new HttpClient()
let req = new HttpRequestMessage(HttpMethod.Post, service + "/tokens")
req.Headers.Add("X-TOTP-Code", code)
req.Headers.Host <- "example.com"
req.Content <- new StringContent("""{"sub":"svc-a","aud":["svc-b"]}""", Encoding.UTF8, "application/json")
let resp = client.Send req
printfn "%d" (int resp.StatusCode)
