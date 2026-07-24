// C# (.NET) — библиотека: Otp.NET (`dotnet add package Otp.NET`)
using OtpNet;
using System.Text;

var secret = Environment.GetEnvironmentVariable("AUTH_TOTP_SECRET")!;   // base32
var service = Environment.GetEnvironmentVariable("JWT_SERVICE_URL") ?? "http://localhost:8080";

var totp = new Totp(Base32Encoding.ToBytes(secret));                    // SHA-1, 6, 30с
var code = totp.ComputeTotp();

using var http = new HttpClient();
var req = new HttpRequestMessage(HttpMethod.Post, $"{service}/tokens")
{
    Content = new StringContent("{\"sub\":\"svc-a\",\"aud\":[\"svc-b\"]}", Encoding.UTF8, "application/json"),
};
req.Headers.Add("X-TOTP-Code", code);
req.Headers.Host = "example.com";
var resp = await http.SendAsync(req);
Console.WriteLine($"{(int)resp.StatusCode} {await resp.Content.ReadAsStringAsync()}");
