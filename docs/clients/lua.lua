--- Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
--
-- Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
-- токена и массовый отзыв токенов субъекта.
--
-- Зависимости: `luaossl` (HMAC), `lua-http` (HTTP), `dkjson` (JSON).
--
-- Окружение:
--
-- * `AUTH_TOTP_SECRET` — общий TOTP-секрет (см. примечание о base32);
-- * `JWT_SERVICE_URL` — базовый URL, по умолчанию `http://localhost:8080`.
--
-- Пример трактует секрет как сырые байты; для совместимости с Google
-- Authenticator добавьте декодер base32.
--
-- **Код считается заново перед каждым запросом.** При включённой на сервере
-- защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление
-- того же кода вернёт 401, хотя сам код ещё не истёк.
--
-- @module jwt_service_client
-- @license MIT

local hmac = require 'openssl.hmac'
local json = require 'dkjson'
local request = require 'http.request'

local M = {}

--- Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
-- @field ISSUER_HOST
M.ISSUER_HOST = 'example.com'

--- Возвращает базовый URL сервиса из окружения.
-- @treturn string URL сервиса.
local function service_url()
  return os.getenv('JWT_SERVICE_URL') or 'http://localhost:8080'
end

--- Вычисляет TOTP-код на текущий момент.
--
-- Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
-- Усечение — по RFC 4226 §5.3.
--
-- @treturn string Код из шести десятичных знаков.
function M.totp_code()
  local secret = os.getenv('AUTH_TOTP_SECRET')
  local counter = math.floor(os.time() / 30)

  -- Счётчик как 8 байт big-endian.
  local message = ''
  for i = 7, 0, -1 do
    message = message .. string.char(math.floor(counter / 2 ^ (8 * i)) % 256)
  end

  local digest = hmac.new(secret, 'sha1'):final(message)
  local offset = (digest:byte(#digest) % 16) + 1

  local code = ((digest:byte(offset) % 128) * 2 ^ 24)
    + (digest:byte(offset + 1) * 2 ^ 16)
    + (digest:byte(offset + 2) * 2 ^ 8)
    + digest:byte(offset + 3)

  return string.format('%06d', code % 1000000)
end

--- Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
--
-- @tparam string method HTTP-метод.
-- @tparam string path Путь ручки, начиная со слеша.
-- @tparam ?table body Тело запроса либо nil, если тела нет.
-- @treturn number HTTP-код ответа.
-- @treturn string Тело ответа.
local function do_request(method, path, body)
  local req = request.new_from_uri(service_url() .. path)
  req.headers:upsert(':method', method)

  -- Код считается здесь, а не переиспользуется: один код — один запрос.
  req.headers:upsert('x-totp-code', M.totp_code())
  req.headers:upsert('host', M.ISSUER_HOST)
  req.headers:upsert('content-type', 'application/json')

  if body then
    req:set_body(json.encode(body))
  end

  local headers, stream = req:go()
  return tonumber(headers:get(':status')), stream:get_body_as_string()
end

--- Выпускает access-токен (`POST /tokens`).
--
-- @tparam string sub Субъект, которому выдаётся токен (claim `sub`).
-- @tparam table aud Список получателей (claim `aud`); не должен быть пустым.
-- @tparam ?boolean with_refresh Запросить refresh-токен для продления сессии.
-- @treturn table Ответ с полями `token` и, если запрашивался, `refresh_token`.
-- @raise Ошибка при 401 (неверный код), 422 (параметры), 500 (JWKS или Redis).
function M.issue_token(sub, aud, with_refresh)
  local status, body = do_request('POST', '/tokens', {
    sub = sub,
    aud = aud,
    refresh = with_refresh or false,
  })

  assert(status == 200, 'выпуск не удался: ' .. status)
  return json.decode(body)
end

--- Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
--
-- Старый токен после обмена недействителен: сохраните новый и выбросьте
-- предыдущий.
--
-- **Внимание:** не повторяйте обмен старым токеном при потере ответа. Повторное
-- предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
-- выданные по ним access-токены. Надёжнее выпустить пару заново.
--
-- @tparam string refresh_token Токен из выпуска или прошлого обмена.
-- @treturn table Новая пара `token` и `refresh_token`.
-- @raise Ошибка при 401 — токен неизвестен, истёк или уже использован.
function M.refresh_tokens(refresh_token)
  local status, body = do_request('POST', '/tokens/refresh', {
    refresh_token = refresh_token,
  })

  assert(status == 200, 'обмен не удался: ' .. status)
  return json.decode(body)
end

--- Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
--
-- Идемпотентно: отзыв несуществующего `jti` — тоже успех.
--
-- @tparam string jti Идентификатор токена из claim `jti`.
-- @raise Ошибка при 500 — хранилище недоступно, отзыв НЕ выполнен.
function M.revoke_token(jti)
  local status = do_request('DELETE', '/tokens/' .. jti, nil)
  assert(status == 204, 'отзыв не удался: ' .. status)
end

--- Отзывает все активные токены субъекта.
--
-- Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить токены
-- по одному нельзя, их `jti` вызывающему неизвестны.
--
-- @tparam string sub Субъект, чьи токены гасятся.
-- @treturn number Число отозванных токенов; истёкшие не считаются.
function M.revoke_subject(sub)
  local status, body = do_request('DELETE', '/subjects/' .. sub .. '/tokens', nil)

  assert(status == 200, 'массовый отзыв не удался: ' .. status)
  return json.decode(body).revoked
end

-- Демонстрация полного жизненного цикла токена.
local issued = M.issue_token('svc-a', { 'svc-b' }, true)
print('выпущен: ' .. issued.token:sub(1, 32) .. '...')

local refreshed = M.refresh_tokens(issued.refresh_token)
print('обновлён: ' .. refreshed.token:sub(1, 32) .. '...')

print('отозвано токенов: ' .. M.revoke_subject('svc-a'))

return M
