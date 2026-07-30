/// Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
///
/// Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
/// токена и массовый отзыв токенов субъекта.
///
/// TOTP считается через HMACSHA1 из .NET, внешних пакетов не требуется.
///
/// Окружение:
/// - `AUTH_TOTP_SECRET` — общий TOTP-секрет (см. примечание о base32);
/// - `JWT_SERVICE_URL` — базовый URL, по умолчанию `http://localhost:8080`.
///
/// Пример трактует секрет как сырые байты (UTF-8); для совместимости с Google
/// Authenticator добавьте декодер base32.
///
/// **Код считается заново перед каждым запросом.** При включённой на сервере
/// защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное
/// предъявление того же кода вернёт `401`, хотя сам код ещё не истёк.
module JwtServiceClient

open System
open System.Net.Http
open System.Security.Cryptography
open System.Text
open System.Text.Json

/// Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
let issuerHost = "example.com"

/// Базовый URL сервиса из окружения.
let serviceUrl =
    match Environment.GetEnvironmentVariable "JWT_SERVICE_URL" with
    | null | "" -> "http://localhost:8080"
    | value -> value

let private http = new HttpClient()

/// Вычисляет TOTP-код на текущий момент.
///
/// Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
/// Усечение — по RFC 4226 §5.3.
///
/// Возвращает код из шести десятичных знаков.
let totpCode () : string =
    let secret = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable "AUTH_TOTP_SECRET")
    let counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30L

    let message = BitConverter.GetBytes counter
    if BitConverter.IsLittleEndian then Array.Reverse message

    use hmac = new HMACSHA1(secret)
    let digest = hmac.ComputeHash message

    let offset = int (digest.[digest.Length - 1] &&& 0x0fuy)
    let code =
        ((int digest.[offset] &&& 0x7f) <<< 24)
        ||| (int digest.[offset + 1] <<< 16)
        ||| (int digest.[offset + 2] <<< 8)
        ||| int digest.[offset + 3]

    sprintf "%06d" (code % 1000000)

/// Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
///
/// `method` — HTTP-метод, `path` — путь ручки, `body` — тело запроса либо `None`.
///
/// Возвращает пару из HTTP-кода и тела ответа.
let request (method: HttpMethod) (path: string) (body: string option) : int * string =
    use message = new HttpRequestMessage(method, serviceUrl + path)

    // Код считается здесь, а не переиспользуется: один код — один запрос.
    message.Headers.Add("X-TOTP-Code", totpCode ())
    message.Headers.Host <- issuerHost

    body
    |> Option.iter (fun content ->
        message.Content <- new StringContent(content, Encoding.UTF8, "application/json"))

    let response = http.Send message
    let text = response.Content.ReadAsStringAsync().Result

    int response.StatusCode, text

/// Выпускает access-токен (`POST /tokens`).
///
/// `sub` — субъект (claim `sub`), `aud` — получатель (claim `aud`),
/// `withRefresh` — запросить refresh-токен для продления сессии,
/// `claimsJson` — произвольные claims JSON-объектом (например `{"role":"admin"}`)
/// либо `None`.
///
/// Произвольные claims попадают в payload рядом с зарегистрированными. Служебные
/// имена (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) переопределять нельзя —
/// сервис ответит `422`.
///
/// Ошибки: `401` — неверный код, `422` — некорректные параметры или запрещённый
/// claim, `500` — недоступны JWKS или Redis.
let issueToken (sub: string) (aud: string) (withRefresh: bool) (claimsJson: string option) : string =
    let claimsPart =
        claimsJson |> Option.map (sprintf ",\"claims\":%s") |> Option.defaultValue ""

    let body =
        sprintf """{"sub":"%s","aud":["%s"],"refresh":%b%s}""" sub aud withRefresh claimsPart

    match request HttpMethod.Post "/tokens" (Some body) with
    | 200, text -> text
    | status, _ -> failwithf "выпуск не удался: %d" status

/// Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
///
/// Старый токен после обмена недействителен: сохраните новый и выбросьте
/// предыдущий.
///
/// **Внимание:** не повторяйте обмен старым токеном при потере ответа. Повторное
/// предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
/// выданные по ним access-токены. Надёжнее выпустить пару заново.
///
/// Ошибка `401` означает, что токен неизвестен, истёк или уже использован.
let refreshTokens (refreshToken: string) : string =
    let body = sprintf """{"refresh_token":"%s"}""" refreshToken

    match request HttpMethod.Post "/tokens/refresh" (Some body) with
    | 200, text -> text
    | status, _ -> failwithf "обмен не удался: %d" status

/// Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
///
/// Идемпотентно: отзыв несуществующего `jti` — тоже успех. Ошибка `500` означает,
/// что хранилище недоступно и отзыв **не выполнен**: попытку следует повторить.
let revokeToken (jti: string) : unit =
    match request HttpMethod.Delete (sprintf "/tokens/%s" jti) None with
    | 204, _ -> ()
    | status, _ -> failwithf "отзыв не удался: %d" status

/// Отзывает все активные токены субъекта.
///
/// Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить токены
/// по одному нельзя, их `jti` вызывающему неизвестны.
///
/// Возвращает число отозванных токенов; истёкшие не считаются.
let revokeSubject (sub: string) : int =
    match request HttpMethod.Delete (sprintf "/subjects/%s/tokens" sub) None with
    | 200, text ->
        use document = JsonDocument.Parse text
        document.RootElement.GetProperty("revoked").GetInt32()
    | status, _ -> failwithf "массовый отзыв не удался: %d" status

// Демонстрация полного жизненного цикла токена.
let issued = issueToken "svc-a" "svc-b" true (Some """{"role":"admin"}""")
printfn "выпущен: %s" issued

// В боевом коде разберите JSON и достаньте refresh_token.
use issuedDocument = JsonDocument.Parse issued
let refreshToken = issuedDocument.RootElement.GetProperty("refresh_token").GetString()

printfn "обновлён: %s" (refreshTokens refreshToken)
printfn "отозвано токенов: %d" (revokeSubject "svc-a")
