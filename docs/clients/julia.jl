"""
Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).

Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
токена и массовый отзыв токенов субъекта.

Зависимости: `using Pkg; Pkg.add(["HTTP", "JSON3"])` (SHA входит в stdlib).

# Окружение
- `AUTH_TOTP_SECRET` — общий TOTP-секрет (см. примечание о base32);
- `JWT_SERVICE_URL` — базовый URL, по умолчанию `http://localhost:8080`.

Пример трактует секрет как сырые байты; для совместимости с Google Authenticator
добавьте декодер base32.

!!! warning "Один код — один запрос"
    Код считается заново перед каждым запросом. При включённой на сервере защите
    от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление того
    же кода вернёт 401, хотя сам код ещё не истёк.
"""
module JwtServiceClient

using HTTP
using JSON3
using SHA

"""Значение claim `iss`. Должно совпадать при выпуске и проверке токена."""
const ISSUER_HOST = "example.com"

"""
    service_url() -> String

Базовый URL сервиса из окружения.
"""
service_url() = get(ENV, "JWT_SERVICE_URL", "http://localhost:8080")

"""
    totp_code() -> String

Вычисляет TOTP-код на текущий момент.

Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
Усечение — по RFC 4226 §5.3.

Возвращает строку из шести десятичных знаков.
"""
function totp_code()
    secret = Vector{UInt8}(ENV["AUTH_TOTP_SECRET"])
    counter = UInt64(floor(time() / 30))
    message = reinterpret(UInt8, [hton(counter)])

    digest = hmac_sha1(secret, collect(message))
    offset = (digest[end] & 0x0f) + 1

    code = (UInt32(digest[offset] & 0x7f) << 24) |
           (UInt32(digest[offset + 1]) << 16) |
           (UInt32(digest[offset + 2]) << 8) |
           UInt32(digest[offset + 3])

    return lpad(code % 1000000, 6, '0')
end

"""
    request(method, path; body=nothing) -> HTTP.Response

Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.

# Аргументы
- `method`: HTTP-метод строкой.
- `path`: путь ручки, начиная со слеша.
- `body`: тело запроса либо `nothing`, если тела нет.
"""
function request(method, path; body = nothing)
    headers = [
        # Код считается здесь, а не переиспользуется: один код — один запрос.
        "X-TOTP-Code" => totp_code(),
        "Host" => ISSUER_HOST,
        "Content-Type" => "application/json",
    ]

    payload = body === nothing ? "" : JSON3.write(body)
    return HTTP.request(method, service_url() * path, headers, payload; status_exception = false)
end

"""
    issue_token(sub, aud; with_refresh=false) -> Dict

Выпускает access-токен (`POST /tokens`).

# Аргументы
- `sub`: субъект, которому выдаётся токен (claim `sub`).
- `aud`: список получателей (claim `aud`); не должен быть пустым.
- `with_refresh`: запросить refresh-токен для продления сессии.

Бросает ошибку при 401 (неверный код), 422 (некорректные параметры) и 500
(недоступны JWKS или Redis).
"""
function issue_token(sub, aud; with_refresh = false)
    response = request("POST", "/tokens"; body = (sub = sub, aud = aud, refresh = with_refresh))
    response.status == 200 || error("выпуск не удался: $(response.status)")

    return JSON3.read(String(response.body), Dict)
end

"""
    refresh_tokens(refresh_token) -> Dict

Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).

Старый токен после обмена недействителен: сохраните новый и выбросьте
предыдущий.

!!! danger "Не ретрайте обмен"
    При потере ответа не повторяйте обмен старым токеном. Повторное предъявление
    трактуется как кража и гасит всю семью — и refresh-токены, и выданные по ним
    access-токены. Надёжнее выпустить пару заново.
"""
function refresh_tokens(refresh_token)
    response = request("POST", "/tokens/refresh"; body = (refresh_token = refresh_token,))
    response.status == 200 || error("обмен не удался: $(response.status)")

    return JSON3.read(String(response.body), Dict)
end

"""
    revoke_token(jti)

Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).

Идемпотентно: отзыв несуществующего `jti` — тоже успех. Ошибка означает, что
хранилище недоступно и отзыв **не выполнен**: попытку следует повторить.
"""
function revoke_token(jti)
    response = request("DELETE", "/tokens/$jti")
    response.status == 204 || error("отзыв не удался: $(response.status)")

    return nothing
end

"""
    revoke_subject(sub) -> Int

Отзывает все активные токены субъекта (`DELETE /subjects/{sub}/tokens`).

Нужен при компрометации: гасить токены по одному нельзя, их `jti` вызывающему
неизвестны. Возвращает число отозванных токенов; истёкшие не считаются.
"""
function revoke_subject(sub)
    response = request("DELETE", "/subjects/$sub/tokens")
    response.status == 200 || error("массовый отзыв не удался: $(response.status)")

    return JSON3.read(String(response.body), Dict)["revoked"]
end

end # module

# Демонстрация полного жизненного цикла токена.
using .JwtServiceClient

issued = JwtServiceClient.issue_token("svc-a", ["svc-b"]; with_refresh = true)
println("выпущен: ", first(issued["token"], 32), "...")

refreshed = JwtServiceClient.refresh_tokens(issued["refresh_token"])
println("обновлён: ", first(refreshed["token"], 32), "...")

println("отозвано токенов: ", JwtServiceClient.revoke_subject("svc-a"))
