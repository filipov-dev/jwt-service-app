# frozen_string_literal: true

# Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
#
# Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
# токена и массовый отзыв токенов субъекта.
#
# Зависимости: gem install rotp
#
# Окружение:
# * +AUTH_TOTP_SECRET+ — общий TOTP-секрет в base32 (обязательно);
# * +JWT_SERVICE_URL+ — базовый URL сервиса, по умолчанию http://localhost:8080.
#
# ВАЖНО: код считается заново перед каждым запросом. При включённой на сервере
# защите от переигрывания (+AUTH_TOTP_REPLAY_PROTECTION+) повторное предъявление
# того же кода вернёт 401, хотя сам код ещё не истёк.

require 'json'
require 'net/http'
require 'rotp'
require 'uri'

# Клиент сервиса выдачи токенов.
class JwtServiceClient
  # Значение claim +iss+. Должно совпадать при выпуске и проверке токена.
  ISSUER_HOST = 'example.com'

  # @param base_url [String] базовый URL сервиса
  # @param secret [String] общий TOTP-секрет в base32
  def initialize(base_url, secret)
    @base_url = base_url
    @totp = ROTP::TOTP.new(secret)
  end

  # Собирает клиент из переменных окружения.
  #
  # @return [JwtServiceClient]
  # @raise [KeyError] если не задан AUTH_TOTP_SECRET
  def self.from_env
    new(ENV.fetch('JWT_SERVICE_URL', 'http://localhost:8080'), ENV.fetch('AUTH_TOTP_SECRET'))
  end

  # Выпускает access-токен (+POST /tokens+).
  #
  # @param sub [String] субъект, которому выдаётся токен (claim +sub+)
  # @param aud [Array<String>] список получателей (claim +aud+), не пустой
  # @param with_refresh [Boolean] запросить refresh для продления сессии
  # @param claims [Hash] произвольные claims (роли, scope, tenant) — попадают в
  #   payload рядом с зарегистрированными. Служебные имена (+iss+, +sub+, +aud+,
  #   +exp+, +iat+, +nbf+, +jti+) переопределять нельзя, будет 422. Число ключей
  #   и объём ограничены на сервере.
  # @return [Hash] +{"token" => ..., "refresh_token" => ...}+
  # @raise [RuntimeError] 401 — неверный код, 422 — параметры или запрещённый
  #   claim, 500 — JWKS/Redis
  def issue_token(sub, aud, with_refresh: false, claims: {})
    body = { sub: sub, aud: aud, refresh: with_refresh }
    body[:claims] = claims unless claims.empty?

    response = request(Net::HTTP::Post, '/tokens', body)
    raise "выпуск не удался: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)
  end

  # Обменивает refresh-токен на новую пару (+POST /tokens/refresh+).
  #
  # Старый токен после обмена недействителен: сохраните новый и выбросьте
  # предыдущий.
  #
  # ВНИМАНИЕ: не повторяйте обмен старым токеном при потере ответа. Повторное
  # предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
  # выданные по ним access-токены. Надёжнее выпустить пару заново.
  #
  # @param refresh_token [String] токен из выпуска или прошлого обмена
  # @return [Hash] новая пара +{"token" => ..., "refresh_token" => ...}+
  # @raise [RuntimeError] 401 — токен неизвестен, истёк или уже использован
  def refresh_tokens(refresh_token)
    response = request(Net::HTTP::Post, '/tokens/refresh', refresh_token: refresh_token)
    raise "обмен не удался: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)
  end

  # Отзывает один токен по его +jti+ (+DELETE /tokens/{jti}+).
  #
  # Идемпотентно: отзыв несуществующего +jti+ — тоже успех.
  #
  # @param jti [String] идентификатор токена из claim +jti+
  # @return [void]
  # @raise [RuntimeError] 500 — хранилище недоступно, отзыв НЕ выполнен
  def revoke_token(jti)
    response = request(Net::HTTP::Delete, "/tokens/#{jti}")
    raise "отзыв не удался: #{response.code}" unless response.code == '204'
  end

  # Отзывает все активные токены субъекта.
  #
  # Ручка +DELETE /subjects/{sub}/tokens+. Нужна при компрометации: гасить токены
  # по одному нельзя, их +jti+ вызывающему неизвестны.
  #
  # @param sub [String] субъект, чьи токены гасятся
  # @return [Integer] число отозванных токенов; истёкшие не считаются
  # @raise [RuntimeError] 500 — хранилище недоступно, отзыв не выполнен
  def revoke_subject(sub)
    response = request(Net::HTTP::Delete, "/subjects/#{sub}/tokens")
    raise "массовый отзыв не удался: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)['revoked']
  end

  private

  # Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
  #
  # @param klass [Class] класс запроса Net::HTTP
  # @param path [String] путь ручки, начиная со слеша
  # @param body [Hash, nil] тело запроса либо nil, если тела нет
  # @return [Net::HTTPResponse]
  def request(klass, path, body = nil)
    uri = URI.join(@base_url, path)
    req = klass.new(uri)

    # Код считается здесь, а не переиспользуется: один код — один запрос.
    req['X-TOTP-Code'] = @totp.now
    req['Host'] = ISSUER_HOST
    req['Content-Type'] = 'application/json'
    req.body = JSON.dump(body) if body

    Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  end
end

if __FILE__ == $PROGRAM_NAME
  client = JwtServiceClient.from_env

  issued = client.issue_token('svc-a', ['svc-b'], with_refresh: true, claims: { role: 'admin' })
  puts "выпущен: #{issued['token'][0, 32]}..."

  refreshed = client.refresh_tokens(issued['refresh_token'])
  puts "обновлён: #{refreshed['token'][0, 32]}..."

  puts "отозвано токенов: #{client.revoke_subject('svc-a')}"
end
