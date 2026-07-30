// Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
//
// Зависимости: dotnet add package Otp.NET
//
// Окружение:
//   AUTH_TOTP_SECRET — общий TOTP-секрет в base32 (обязательно);
//   JWT_SERVICE_URL  — базовый URL сервиса, по умолчанию http://localhost:8080.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using OtpNet;

/// <summary>Ответ на выпуск токена или обмен refresh-токена.</summary>
public sealed record TokenResponse(
    /// <summary>Подписанный JWT в формате header.payload.signature.</summary>
    [property: JsonPropertyName("token")] string Token,
    /// <summary>Refresh-токен; присутствует, только если запрашивался.</summary>
    [property: JsonPropertyName("refresh_token")] string? RefreshToken);

/// <summary>Ответ на массовый отзыв токенов субъекта.</summary>
public sealed record RevokeGroupResponse(
    /// <summary>Сколько активных токенов отозвано; истёкшие не считаются.</summary>
    [property: JsonPropertyName("revoked")] int Revoked);

/// <summary>
/// Клиент сервиса выдачи токенов, покрывающий все четыре ручки уровня 3.
/// </summary>
/// <remarks>
/// TOTP-код считается <b>заново перед каждым запросом</b>. При включённой на
/// сервере защите от переигрывания (<c>AUTH_TOTP_REPLAY_PROTECTION</c>) повторное
/// предъявление того же кода вернёт <c>401</c>, хотя сам код ещё не истёк.
/// </remarks>
public sealed class JwtServiceClient
{
    /// <summary>Значение claim <c>iss</c>. Должно совпадать при выпуске и проверке.</summary>
    private const string IssuerHost = "example.com";

    private readonly string _baseUrl;
    private readonly Totp _totp;
    private readonly HttpClient _http = new();

    /// <summary>Создаёт клиент.</summary>
    /// <param name="baseUrl">Базовый URL сервиса.</param>
    /// <param name="secret">Общий TOTP-секрет в base32.</param>
    public JwtServiceClient(string baseUrl, string secret)
    {
        _baseUrl = baseUrl;
        // Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 с.
        _totp = new Totp(Base32Encoding.ToBytes(secret));
    }

    /// <summary>Собирает клиент из переменных окружения.</summary>
    /// <returns>Готовый клиент.</returns>
    /// <exception cref="InvalidOperationException">Не задан AUTH_TOTP_SECRET.</exception>
    public static JwtServiceClient FromEnv()
    {
        var service = Environment.GetEnvironmentVariable("JWT_SERVICE_URL")
                      ?? "http://localhost:8080";
        var secret = Environment.GetEnvironmentVariable("AUTH_TOTP_SECRET")
                     ?? throw new InvalidOperationException("нужен AUTH_TOTP_SECRET");

        return new JwtServiceClient(service, secret);
    }

    /// <summary>Собирает запрос со свежим TOTP-кодом.</summary>
    /// <param name="method">HTTP-метод.</param>
    /// <param name="path">Путь ручки, начиная со слеша.</param>
    /// <returns>Готовый к отправке запрос.</returns>
    private HttpRequestMessage Request(HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, _baseUrl + path);

        // Код считается здесь, а не переиспользуется: один код — один запрос.
        request.Headers.Add("X-TOTP-Code", _totp.ComputeTotp());
        request.Headers.Host = IssuerHost;

        return request;
    }

    /// <summary>Выпускает access-токен (<c>POST /tokens</c>).</summary>
    /// <param name="sub">Субъект, которому выдаётся токен (claim <c>sub</c>).</param>
    /// <param name="aud">Список получателей (claim <c>aud</c>); не должен быть пустым.</param>
    /// <param name="withRefresh">Запросить refresh-токен для продления сессии.</param>
    /// <param name="claims">
    /// Произвольные claims (роли, scope, tenant) — попадают в payload рядом с
    /// зарегистрированными. Служебные имена (<c>iss</c>, <c>sub</c>, <c>aud</c>,
    /// <c>exp</c>, <c>iat</c>, <c>nbf</c>, <c>jti</c>) переопределять нельзя:
    /// сервис ответит <c>422</c>. Число ключей и объём ограничены на сервере.
    /// </param>
    /// <returns>Выпущенный токен и, если запрашивался, refresh-токен.</returns>
    /// <exception cref="HttpRequestException">
    /// <c>401</c> — неверный код, <c>422</c> — параметры или запрещённый claim,
    /// <c>500</c> — JWKS или Redis.
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
               ?? throw new InvalidOperationException("пустой ответ");
    }

    /// <summary>Обменивает refresh-токен на новую пару (<c>POST /tokens/refresh</c>).</summary>
    /// <remarks>
    /// Старый токен после обмена недействителен: сохраните новый и выбросьте
    /// предыдущий.
    /// <para>
    /// <b>Внимание:</b> не повторяйте обмен старым токеном при потере ответа.
    /// Повторное предъявление трактуется как кража и гасит всю семью — и
    /// refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
    /// заново.
    /// </para>
    /// </remarks>
    /// <param name="refreshToken">Токен из выпуска или прошлого обмена.</param>
    /// <returns>Новая пара access + refresh.</returns>
    /// <exception cref="HttpRequestException">
    /// <c>401</c> — токен неизвестен, истёк или уже использован.
    /// </exception>
    public async Task<TokenResponse> RefreshTokensAsync(string refreshToken)
    {
        var request = Request(HttpMethod.Post, "/tokens/refresh");
        request.Content = JsonContent.Create(new { refresh_token = refreshToken });

        var response = await _http.SendAsync(request);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<TokenResponse>()
               ?? throw new InvalidOperationException("пустой ответ");
    }

    /// <summary>Отзывает один токен по его <c>jti</c> (<c>DELETE /tokens/{jti}</c>).</summary>
    /// <remarks>Идемпотентно: отзыв несуществующего <c>jti</c> — тоже успех.</remarks>
    /// <param name="jti">Идентификатор токена из claim <c>jti</c>.</param>
    /// <exception cref="HttpRequestException">
    /// <c>500</c> — хранилище недоступно, отзыв НЕ выполнен: повторите попытку.
    /// </exception>
    public async Task RevokeTokenAsync(string jti)
    {
        var response = await _http.SendAsync(Request(HttpMethod.Delete, $"/tokens/{jti}"));
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Отзывает все активные токены субъекта.</summary>
    /// <remarks>
    /// Ручка <c>DELETE /subjects/{sub}/tokens</c>. Нужна при компрометации: гасить
    /// токены по одному нельзя, их <c>jti</c> вызывающему неизвестны.
    /// </remarks>
    /// <param name="sub">Субъект, чьи токены гасятся.</param>
    /// <returns>Число отозванных токенов; истёкшие не считаются.</returns>
    /// <exception cref="HttpRequestException">
    /// <c>500</c> — хранилище недоступно, отзыв не выполнен.
    /// </exception>
    public async Task<int> RevokeSubjectAsync(string sub)
    {
        var response = await _http.SendAsync(Request(HttpMethod.Delete, $"/subjects/{sub}/tokens"));
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<RevokeGroupResponse>();
        return body?.Revoked ?? 0;
    }
}

/// <summary>Демонстрирует полный жизненный цикл токена.</summary>
public static class Program
{
    /// <summary>Точка входа.</summary>
    public static async Task Main()
    {
        var client = JwtServiceClient.FromEnv();

        var issued = await client.IssueTokenAsync(
            "svc-a", new[] { "svc-b" }, withRefresh: true,
            claims: new Dictionary<string, object> { ["role"] = "admin" });
        Console.WriteLine($"выпущен: {issued.Token[..32]}...");

        var refreshed = await client.RefreshTokensAsync(issued.RefreshToken!);
        Console.WriteLine($"обновлён: {refreshed.Token[..32]}...");

        Console.WriteLine($"отозвано токенов: {await client.RevokeSubjectAsync("svc-a")}");
    }
}
