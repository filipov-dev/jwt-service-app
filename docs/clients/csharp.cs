// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//
// Install: dotnet add package Otp.NET
//
// Env:
//   AUTH_TOTP_SECRET — shared TOTP secret, base32 (required);
//   JWT_SERVICE_URL  — service base URL, default http://localhost:8080.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using OtpNet;

/// <summary>Reply of an issue or a refresh call.</summary>
public sealed record TokenResponse(
    /// <summary>Signed JWT: header.payload.signature.</summary>
    [property: JsonPropertyName("token")] string Token,
    /// <summary>Refresh token; present only if it was requested.</summary>
    [property: JsonPropertyName("refresh_token")] string? RefreshToken);

/// <summary>Reply of a bulk revoke call.</summary>
public sealed record RevokeGroupResponse(
    /// <summary>How many active tokens were revoked; expired ones do not count.</summary>
    [property: JsonPropertyName("revoked")] int Revoked);

/// <summary>
/// Client of the token service, covering all four level 3 endpoints.
/// </summary>
/// <remarks>
/// The code is recomputed <b>before every request</b>. With replay protection on
/// (<c>AUTH_TOTP_REPLAY_PROTECTION</c>) the server rejects a code it has already
/// seen with <c>401</c>, even while that code is still inside its time window.
/// </remarks>
public sealed class JwtServiceClient
{
    /// <summary>
    /// Sent as the Host header and becomes the <c>iss</c> claim. Must be the
    /// same on issue and on verify, or the token will not verify.
    /// </summary>
    private const string IssuerHost = "example.com";

    private readonly string _baseUrl;
    private readonly Totp _totp;
    private readonly HttpClient _http = new();

    /// <summary>Creates a client.</summary>
    /// <param name="baseUrl">Service base URL.</param>
    /// <param name="secret">Shared TOTP secret, base32.</param>
    public JwtServiceClient(string baseUrl, string secret)
    {
        _baseUrl = baseUrl;
        // Service defaults: SHA-1, 6 digits, 30-second step.
        _totp = new Totp(Base32Encoding.ToBytes(secret));
    }

    /// <summary>Builds a client from the environment.</summary>
    /// <returns>The client.</returns>
    /// <exception cref="InvalidOperationException">AUTH_TOTP_SECRET is not set.</exception>
    public static JwtServiceClient FromEnv()
    {
        var service = Environment.GetEnvironmentVariable("JWT_SERVICE_URL")
                      ?? "http://localhost:8080";
        var secret = Environment.GetEnvironmentVariable("AUTH_TOTP_SECRET")
                     ?? throw new InvalidOperationException("AUTH_TOTP_SECRET is required");

        return new JwtServiceClient(service, secret);
    }

    /// <summary>
    /// Builds a request with a code computed here rather than reused: one code,
    /// one request.
    /// </summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="path">Endpoint path.</param>
    /// <returns>The request, ready to send.</returns>
    private HttpRequestMessage Request(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, _baseUrl + path);

        request.Headers.Add("X-TOTP-Code", _totp.ComputeTotp());
        request.Headers.Host = IssuerHost;

        return request;
    }

    /// <summary>Issues an access token (<c>POST /tokens</c>).</summary>
    /// <param name="sub">Subject the token is issued to (<c>sub</c> claim).</param>
    /// <param name="aud">Audience (<c>aud</c> claim); must not be empty.</param>
    /// <param name="withRefresh">Also return a refresh token for extending the session.</param>
    /// <param name="claims">
    /// Custom claims (role, scope, tenant). They sit next to the registered
    /// ones, so the consumer reads <c>role</c>, not <c>extra.role</c>. Reserved
    /// names (<c>iss</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>, <c>iat</c>,
    /// <c>nbf</c>, <c>jti</c>) are rejected with <c>422</c> — change lifetime
    /// through <c>ttl</c>, not <c>exp</c>. Count and size are capped server-side.
    /// </param>
    /// <returns>The issued token and, if requested, a refresh token.</returns>
    /// <exception cref="HttpRequestException">
    /// <c>401</c> bad code, <c>422</c> bad parameters or forbidden claim,
    /// <c>500</c> JWKS or Redis unavailable.
    /// </exception>
    public async Task<TokenResponse> IssueTokenAsync(
        string sub,
        string[] aud,
        bool withRefresh = false,
        IDictionary<string, object>? claims = null)
    {
        var request = Request(HttpMethod.Post, "/tokens");
        request.Content = claims is null or { Count: 0 }
            ? JsonContent.Create(new { sub, aud, refresh = withRefresh })
            : JsonContent.Create(new { sub, aud, refresh = withRefresh, claims });

        var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<TokenResponse>()
               ?? throw new InvalidOperationException("empty response");
    }

    /// <summary>Exchanges a refresh token for a new pair (<c>POST /tokens/refresh</c>).</summary>
    /// <remarks>
    /// The old token dies on exchange: store the new one and drop the previous.
    /// <para>
    /// <b>Never retry</b> an exchange with the old token when the reply is lost.
    /// A second presentation reads as theft, and the server revokes the whole
    /// family — refresh tokens and the access tokens issued from them. Issue a
    /// new pair instead.
    /// </para>
    /// </remarks>
    /// <param name="refreshToken">Token from an issue or a previous exchange.</param>
    /// <returns>The new access + refresh pair.</returns>
    /// <exception cref="HttpRequestException">
    /// <c>401</c> — token unknown, expired or already used.
    /// </exception>
    public async Task<TokenResponse> RefreshTokensAsync(string refreshToken)
    {
        var request = Request(HttpMethod.Post, "/tokens/refresh");
        request.Content = JsonContent.Create(new { refresh_token = refreshToken });

        var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<TokenResponse>()
               ?? throw new InvalidOperationException("empty response");
    }

    /// <summary>Revokes one token by its <c>jti</c> (<c>DELETE /tokens/{jti}</c>).</summary>
    /// <remarks>
    /// Idempotent: revoking an unknown <c>jti</c> is success too — the desired
    /// state holds either way.
    /// </remarks>
    /// <param name="jti">Token id from the <c>jti</c> claim.</param>
    /// <exception cref="HttpRequestException">
    /// <c>500</c> — store unreachable, the token is NOT revoked: retry.
    /// </exception>
    public async Task RevokeTokenAsync(string jti)
    {
        var response = await _http.SendAsync(Request(HttpMethod.Delete, $"/tokens/{jti}"));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Revokes every active token of a subject.</summary>
    /// <remarks>
    /// Endpoint <c>DELETE /subjects/{sub}/tokens</c>. The compromise path:
    /// tokens cannot be killed one by one because the caller does not know
    /// their <c>jti</c>.
    /// </remarks>
    /// <param name="sub">Subject whose tokens are killed.</param>
    /// <returns>Number of revoked tokens; expired ones do not count.</returns>
    /// <exception cref="HttpRequestException">
    /// <c>500</c> — store unreachable, nothing was revoked.
    /// </exception>
    public async Task<int> RevokeSubjectAsync(string sub)
    {
        var response = await _http.SendAsync(Request(HttpMethod.Delete, $"/subjects/{sub}/tokens"));
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<RevokeGroupResponse>();
        return body?.Revoked ?? 0;
    }
}

/// <summary>Full token lifecycle: issue, refresh, bulk revoke.</summary>
public static class Program
{
    /// <summary>Entry point.</summary>
    public static async Task Main()
    {
        var client = JwtServiceClient.FromEnv();

        var issued = await client.IssueTokenAsync(
            "svc-a", new[] { "svc-b" }, withRefresh: true,
            claims: new Dictionary<string, object> { ["role"] = "admin" });
        Console.WriteLine($"issued: {issued.Token[..32]}...");

        var refreshed = await client.RefreshTokensAsync(issued.RefreshToken!);
        Console.WriteLine($"refreshed: {refreshed.Token[..32]}...");

        Console.WriteLine($"revoked: {await client.RevokeSubjectAsync("svc-a")}");
    }
}
