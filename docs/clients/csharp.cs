// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//
// Install: dotnet add package Otp.NET
// Env: AUTH_TOTP_SECRET (base32), JWT_SERVICE_URL (default http://localhost:8080).
// See README.md for endpoints, error codes and client rules.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using OtpNet;

/// <summary>Reply of an issue or refresh call.</summary>
public sealed record TokenResponse(
    /// <summary>Signed JWT: header.payload.signature.</summary>
    [property: JsonPropertyName("token")] string Token,
    /// <summary>Present only when a refresh token was requested.</summary>
    [property: JsonPropertyName("refresh_token")] string? RefreshToken);

/// <summary>Reply of a bulk revoke call.</summary>
public sealed record RevokeGroupResponse(
    /// <summary>Number of revoked tokens.</summary>
    [property: JsonPropertyName("revoked")] int Revoked);

/// <summary>Client of the token service, covering all four level 3 endpoints.</summary>
public sealed class JwtServiceClient
{
    /// <summary>Sent as the Host header, becomes the <c>iss</c> claim.</summary>
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

    /// <summary>Builds a request with a code computed right before the call.</summary>
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

    /// <summary><c>POST /tokens</c></summary>
    /// <param name="sub">Subject.</param>
    /// <param name="aud">Audience.</param>
    /// <param name="withRefresh">Also ask for a refresh token.</param>
    /// <param name="claims">Custom claims, or <c>null</c>.</param>
    /// <returns>The issued token and, if requested, a refresh token.</returns>
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

    /// <summary>
    /// <c>POST /tokens/refresh</c> — returns a new pair; the old refresh token
    /// is dead once the call succeeds.
    /// </summary>
    /// <param name="refreshToken">Token from an issue or a previous refresh.</param>
    /// <returns>The new access + refresh pair.</returns>
    public async Task<TokenResponse> RefreshTokensAsync(string refreshToken)
    {
        var request = Request(HttpMethod.Post, "/tokens/refresh");
        request.Content = JsonContent.Create(new { refresh_token = refreshToken });

        var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<TokenResponse>()
               ?? throw new InvalidOperationException("empty response");
    }

    /// <summary><c>DELETE /tokens/{jti}</c> — idempotent.</summary>
    /// <param name="jti">Token id from the <c>jti</c> claim.</param>
    public async Task RevokeTokenAsync(string jti)
    {
        var response = await _http.SendAsync(Request(HttpMethod.Delete, $"/tokens/{jti}"));
        response.EnsureSuccessStatusCode();
    }

    /// <summary><c>DELETE /subjects/{sub}/tokens</c></summary>
    /// <param name="sub">Subject whose tokens are revoked.</param>
    /// <returns>Number of revoked tokens.</returns>
    public async Task<int> RevokeSubjectAsync(string sub)
    {
        var response = await _http.SendAsync(Request(HttpMethod.Delete, $"/subjects/{sub}/tokens"));
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<RevokeGroupResponse>();
        return body?.Revoked ?? 0;
    }
}

/// <summary>Issue -> refresh -> revoke.</summary>
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
