' jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
'
' TOTP is computed with .NET HMACSHA1, no external packages needed.
'
' Environment:
'   AUTH_TOTP_SECRET — shared TOTP secret (see the base32 note below);
'   JWT_SERVICE_URL  — base URL, default http://localhost:8080.
'
' This example treats the secret as raw UTF-8 bytes; add a base32 decoder for
' Google Authenticator compatibility.

Imports System
Imports System.Net.Http
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.Json

''' <summary>
''' Client of the token service, covering all four level 3 endpoints.
''' </summary>
''' <remarks>
''' The code is recomputed <b>before every request</b>. With replay protection on
''' (<c>AUTH_TOTP_REPLAY_PROTECTION</c>) the server rejects a code it has already
''' seen with <c>401</c>, even while that code is still inside its time window.
''' </remarks>
Public Class JwtServiceClient

    ''' <summary>
    ''' Sent as the Host header and becomes the <c>iss</c> claim. Must be the
    ''' same on issue and on verify, or the token will not verify.
    ''' </summary>
    Private Const IssuerHost As String = "example.com"

    Private ReadOnly _baseUrl As String
    Private ReadOnly _secret As Byte()
    Private ReadOnly _http As New HttpClient()

    ''' <summary>Creates a client.</summary>
    ''' <param name="baseUrl">Service base URL.</param>
    ''' <param name="secret">Shared TOTP secret.</param>
    Public Sub New(baseUrl As String, secret As String)
        _baseUrl = baseUrl
        _secret = Encoding.UTF8.GetBytes(secret)
    End Sub

    ''' <summary>Builds a client from the environment.</summary>
    ''' <returns>The client.</returns>
    ''' <exception cref="InvalidOperationException">AUTH_TOTP_SECRET is not set.</exception>
    Public Shared Function FromEnv() As JwtServiceClient
        Dim service = Environment.GetEnvironmentVariable("JWT_SERVICE_URL")
        If String.IsNullOrEmpty(service) Then service = "http://localhost:8080"

        Dim secret = Environment.GetEnvironmentVariable("AUTH_TOTP_SECRET")
        If String.IsNullOrEmpty(secret) Then
            Throw New InvalidOperationException("AUTH_TOTP_SECRET is required")
        End If

        Return New JwtServiceClient(service, secret)
    End Function

    ''' <summary>Computes a fresh TOTP code for right now.</summary>
    ''' <returns>Six decimal digits.</returns>
    ''' <remarks>
    ''' Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
    ''' RFC 4226 section 5.3.
    ''' </remarks>
    Private Function TotpCode() As String
        Dim counter As Long = DateTimeOffset.UtcNow.ToUnixTimeSeconds() \ 30

        Dim message = BitConverter.GetBytes(counter)
        If BitConverter.IsLittleEndian Then Array.Reverse(message)

        Using hmac As New HMACSHA1(_secret)
            Dim digest = hmac.ComputeHash(message)

            Dim offset As Integer = digest(digest.Length - 1) And &H0F
            Dim code As Integer =
                ((digest(offset) And &H7F) << 24) Or
                (digest(offset + 1) << 16) Or
                (digest(offset + 2) << 8) Or
                digest(offset + 3)

            Return (code Mod 1000000).ToString("D6")
        End Using
    End Function

    ''' <summary>Sends a level 3 request.</summary>
    ''' <param name="method">HTTP method.</param>
    ''' <param name="path">Endpoint path.</param>
    ''' <param name="body">Request body, or <c>Nothing</c> when there is none.</param>
    ''' <returns>HTTP status and response body.</returns>
    Private Function Request(method As HttpMethod, path As String, body As String) _
        As (Status As Integer, Body As String)

        Using message As New HttpRequestMessage(method, _baseUrl & path)
            ' Computed here rather than reused: one code, one request.
            message.Headers.Add("X-TOTP-Code", TotpCode())
            message.Headers.Host = IssuerHost

            If body IsNot Nothing Then
                message.Content = New StringContent(body, Encoding.UTF8, "application/json")
            End If

            Dim response = _http.Send(message)
            Return (CInt(response.StatusCode), response.Content.ReadAsStringAsync().Result)
        End Using
    End Function

    ''' <summary>Issues an access token (<c>POST /tokens</c>).</summary>
    ''' <param name="subject">Subject the token is issued to (claim <c>sub</c>).</param>
    ''' <param name="audience">Audience (claim <c>aud</c>).</param>
    ''' <param name="withRefresh">Also return a refresh token for extending the session.</param>
    ''' <param name="claimsJson">
    ''' Custom claims as a JSON object (for example <c>{"role":"admin"}</c>) or
    ''' <c>Nothing</c>. They sit next to the registered ones, so the consumer
    ''' reads <c>role</c>, not <c>extra.role</c>; reserved names (<c>iss</c>,
    ''' <c>sub</c>, <c>aud</c>, <c>exp</c>, <c>iat</c>, <c>nbf</c>, <c>jti</c>)
    ''' give <c>422</c> — change lifetime through <c>ttl</c>, not <c>exp</c>.
    ''' </param>
    ''' <returns>Response body with <c>token</c> and, if requested, <c>refresh_token</c>.</returns>
    ''' <exception cref="InvalidOperationException">
    ''' <c>401</c> bad code, <c>422</c> bad parameters or forbidden claim,
    ''' <c>500</c> JWKS or Redis unavailable.
    ''' </exception>
    Public Function IssueToken(subject As String, audience As String,
                               Optional withRefresh As Boolean = False,
                               Optional claimsJson As String = Nothing) As String

        Dim claimsPart = If(claimsJson Is Nothing, "", $",""claims"":{claimsJson}")
        Dim body = $"{{""sub"":""{subject}"",""aud"":[""{audience}""],""refresh"":{withRefresh.ToString().ToLower()}{claimsPart}}}"
        Dim result = Request(HttpMethod.Post, "/tokens", body)

        If result.Status <> 200 Then
            Throw New InvalidOperationException($"issue failed: {result.Status}")
        End If

        Return result.Body
    End Function

    ''' <summary>Exchanges a refresh token for a new pair (<c>POST /tokens/refresh</c>).</summary>
    ''' <param name="refreshToken">Token from an issue or a previous exchange.</param>
    ''' <returns>Response body with the new pair.</returns>
    ''' <remarks>
    ''' The old token dies on exchange: store the new one and drop the previous.
    ''' <para>
    ''' <b>Never retry</b> an exchange with the old token when the reply is lost.
    ''' A second presentation reads as theft, and the server revokes the whole
    ''' family — refresh tokens and the access tokens issued from them. Issue a
    ''' new pair instead.
    ''' </para>
    ''' </remarks>
    ''' <exception cref="InvalidOperationException">
    ''' <c>401</c> — token unknown, expired or already used.
    ''' </exception>
    Public Function RefreshTokens(refreshToken As String) As String
        Dim body = $"{{""refresh_token"":""{refreshToken}""}}"
        Dim result = Request(HttpMethod.Post, "/tokens/refresh", body)

        If result.Status <> 200 Then
            Throw New InvalidOperationException($"refresh failed: {result.Status}")
        End If

        Return result.Body
    End Function

    ''' <summary>Revokes one token by its <c>jti</c> (<c>DELETE /tokens/{jti}</c>).</summary>
    ''' <param name="jti">Token id from the <c>jti</c> claim.</param>
    ''' <remarks>Idempotent: revoking an unknown <c>jti</c> is success too.</remarks>
    ''' <exception cref="InvalidOperationException">
    ''' <c>500</c> — store unreachable, the token is NOT revoked: retry.
    ''' </exception>
    Public Sub RevokeToken(jti As String)
        Dim result = Request(HttpMethod.Delete, $"/tokens/{jti}", Nothing)

        If result.Status <> 204 Then
            Throw New InvalidOperationException($"revoke failed: {result.Status}")
        End If
    End Sub

    ''' <summary>Revokes every active token of a subject.</summary>
    ''' <param name="subject">Subject whose tokens are killed.</param>
    ''' <returns>Number of revoked tokens; expired ones do not count.</returns>
    ''' <remarks>
    ''' Endpoint <c>DELETE /subjects/{sub}/tokens</c>. The compromise path:
    ''' tokens cannot be killed one by one because the caller does not know
    ''' their <c>jti</c>.
    ''' </remarks>
    Public Function RevokeSubject(subject As String) As Integer
        Dim result = Request(HttpMethod.Delete, $"/subjects/{subject}/tokens", Nothing)

        If result.Status <> 200 Then
            Throw New InvalidOperationException($"bulk revoke failed: {result.Status}")
        End If

        Using document = JsonDocument.Parse(result.Body)
            Return document.RootElement.GetProperty("revoked").GetInt32()
        End Using
    End Function

End Class

''' <summary>Full token lifecycle: issue, refresh, bulk revoke.</summary>
Module Program
    ''' <summary>Entry point.</summary>
    Sub Main()
        Dim client = JwtServiceClient.FromEnv()

        Dim issued = client.IssueToken("svc-a", "svc-b", withRefresh:=True,
                                       claimsJson:="{""role"":""admin""}")
        Console.WriteLine($"issued: {issued}")

        Using document = JsonDocument.Parse(issued)
            Dim refreshToken = document.RootElement.GetProperty("refresh_token").GetString()
            Console.WriteLine($"refreshed: {client.RefreshTokens(refreshToken)}")
        End Using

        Console.WriteLine($"revoked: {client.RevokeSubject("svc-a")}")
    End Sub
End Module
