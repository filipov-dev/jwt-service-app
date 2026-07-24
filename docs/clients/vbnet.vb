' Visual Basic .NET — TOTP через HMACSHA1 (.NET) + HttpClient.
' AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (UTF-8). Для base32 добавьте декодер.
Imports System
Imports System.Net.Http
Imports System.Security.Cryptography
Imports System.Text

Module Totp
    Sub Main()
        Dim secret = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("AUTH_TOTP_SECRET"))
        Dim service = If(Environment.GetEnvironmentVariable("JWT_SERVICE_URL"), "http://localhost:8080")

        Dim counter As Long = DateTimeOffset.UtcNow.ToUnixTimeSeconds() \ 30
        Dim msg = BitConverter.GetBytes(Net.IPAddress.HostToNetworkOrder(counter))
        Using hmac As New HMACSHA1(secret)
            Dim hs = hmac.ComputeHash(msg)
            Dim off = hs(hs.Length - 1) And &HF
            Dim bin = ((CInt(hs(off)) And &H7F) << 24) Or (CInt(hs(off + 1)) << 16) _
                      Or (CInt(hs(off + 2)) << 8) Or CInt(hs(off + 3))
            Dim code = (bin Mod 1000000).ToString("D6")

            Using client As New HttpClient()
                Dim req As New HttpRequestMessage(HttpMethod.Post, service & "/tokens")
                req.Headers.Add("X-TOTP-Code", code)
                req.Headers.Host = "example.com"
                req.Content = New StringContent("{""sub"":""svc-a"",""aud"":[""svc-b""]}", Encoding.UTF8, "application/json")
                Console.WriteLine(CInt(client.Send(req).StatusCode))
            End Using
        End Using
    End Sub
End Module
