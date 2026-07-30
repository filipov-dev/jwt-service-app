/**
 * Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
 * токена и массовый отзыв токенов субъекта.
 *
 * Зависимости подтягиваются через {@code @Grab}.
 *
 * Окружение:
 * <ul>
 *   <li>{@code AUTH_TOTP_SECRET} — общий TOTP-секрет в base32 (обязательно);</li>
 *   <li>{@code JWT_SERVICE_URL} — базовый URL, по умолчанию {@code http://localhost:8080}.</li>
 * </ul>
 *
 * <b>Код считается заново перед каждым запросом.</b> При включённой на сервере
 * защите от переигрывания ({@code AUTH_TOTP_REPLAY_PROTECTION}) повторное
 * предъявление того же кода вернёт {@code 401}, хотя сам код ещё не истёк.
 */
@Grab('com.eatthepath:java-otp:0.4.0')
@Grab('commons-codec:commons-codec:1.16.0')
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.apache.commons.codec.binary.Base32

import javax.crypto.spec.SecretKeySpec
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant

/**
 * Клиент сервиса выдачи токенов.
 */
class JwtServiceClient {

    /** Значение claim {@code iss}. Должно совпадать при выпуске и проверке. */
    static final String ISSUER_HOST = 'example.com'

    private final String baseUrl
    private final SecretKeySpec key
    private final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator()
    private final HttpClient http = HttpClient.newHttpClient()

    /**
     * Создаёт клиент.
     *
     * @param baseUrl базовый URL сервиса
     * @param secret общий TOTP-секрет в base32
     */
    JwtServiceClient(String baseUrl, String secret) {
        this.baseUrl = baseUrl
        this.key = new SecretKeySpec(new Base32().decode(secret), 'HmacSHA1')
    }

    /**
     * Собирает клиент из переменных окружения.
     *
     * @return готовый клиент
     */
    static JwtServiceClient fromEnv() {
        def secret = System.getenv('AUTH_TOTP_SECRET')
        assert secret != null, 'нужен AUTH_TOTP_SECRET'

        new JwtServiceClient(System.getenv('JWT_SERVICE_URL') ?: 'http://localhost:8080', secret)
    }

    /**
     * Вычисляет TOTP-код на текущий момент.
     *
     * Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
     *
     * @return код из шести десятичных знаков
     */
    private String totpCode() {
        totp.generateOneTimePasswordString(key, Instant.now())
    }

    /**
     * Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
     *
     * @param method HTTP-метод
     * @param path путь ручки, начиная со слеша
     * @param body тело запроса либо {@code null}, если тела нет
     * @return ответ сервиса
     */
    private HttpResponse<String> request(String method, String path, String body) {
        def publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body)

        def request = HttpRequest.newBuilder(URI.create("$baseUrl$path"))
                // Код считается здесь, а не переиспользуется: один код — один запрос.
                .header('X-TOTP-Code', totpCode())
                .header('Host', ISSUER_HOST)
                .header('Content-Type', 'application/json')
                .method(method, publisher)
                .build()

        http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    /**
     * Выпускает access-токен ({@code POST /tokens}).
     *
     * @param sub субъект, которому выдаётся токен (claim {@code sub})
     * @param aud список получателей (claim {@code aud}); не должен быть пустым
     * @param withRefresh запросить refresh-токен для продления сессии
     * @return разобранное тело ответа с полями {@code token} и,
     *         если запрашивался, {@code refresh_token}
     * @throws IllegalStateException {@code 401} — неверный код,
     *         {@code 422} — параметры, {@code 500} — JWKS или Redis
     */
    Map issueToken(String sub, List<String> aud, boolean withRefresh = false) {
        def body = JsonOutput.toJson([sub: sub, aud: aud, refresh: withRefresh])
        def response = request('POST', '/tokens', body)

        if (response.statusCode() != 200) {
            throw new IllegalStateException("выпуск не удался: ${response.statusCode()}")
        }

        new JsonSlurper().parseText(response.body()) as Map
    }

    /**
     * Обменивает refresh-токен на новую пару ({@code POST /tokens/refresh}).
     *
     * Старый токен после обмена недействителен: сохраните новый и выбросьте
     * предыдущий.
     *
     * <b>Внимание:</b> не повторяйте обмен старым токеном при потере ответа.
     * Повторное предъявление трактуется как кража и гасит всю семью — и
     * refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
     * заново.
     *
     * @param refreshToken токен из выпуска или прошлого обмена
     * @return новая пара access + refresh
     * @throws IllegalStateException {@code 401} — токен неизвестен, истёк или
     *         уже использован
     */
    Map refreshTokens(String refreshToken) {
        def body = JsonOutput.toJson([refresh_token: refreshToken])
        def response = request('POST', '/tokens/refresh', body)

        if (response.statusCode() != 200) {
            throw new IllegalStateException("обмен не удался: ${response.statusCode()}")
        }

        new JsonSlurper().parseText(response.body()) as Map
    }

    /**
     * Отзывает один токен по его {@code jti} ({@code DELETE /tokens/{jti}}).
     *
     * Идемпотентно: отзыв несуществующего {@code jti} — тоже успех.
     *
     * @param jti идентификатор токена из claim {@code jti}
     * @throws IllegalStateException {@code 500} — хранилище недоступно, отзыв
     *         НЕ выполнен: повторите попытку
     */
    void revokeToken(String jti) {
        def response = request('DELETE', "/tokens/$jti", null)

        if (response.statusCode() != 204) {
            throw new IllegalStateException("отзыв не удался: ${response.statusCode()}")
        }
    }

    /**
     * Отзывает все активные токены субъекта.
     *
     * Ручка {@code DELETE /subjects/{sub}/tokens}. Нужна при компрометации:
     * гасить токены по одному нельзя, их {@code jti} вызывающему неизвестны.
     *
     * @param sub субъект, чьи токены гасятся
     * @return число отозванных токенов; истёкшие не считаются
     * @throws IllegalStateException {@code 500} — хранилище недоступно
     */
    int revokeSubject(String sub) {
        def response = request('DELETE', "/subjects/$sub/tokens", null)

        if (response.statusCode() != 200) {
            throw new IllegalStateException("массовый отзыв не удался: ${response.statusCode()}")
        }

        (new JsonSlurper().parseText(response.body()) as Map).revoked as int
    }
}

// Демонстрация полного жизненного цикла токена.
def client = JwtServiceClient.fromEnv()

def issued = client.issueToken('svc-a', ['svc-b'], true)
println "выпущен: ${issued.token.take(32)}..."

def refreshed = client.refreshTokens(issued.refresh_token as String)
println "обновлён: ${refreshed.token.take(32)}..."

println "отозвано токенов: ${client.revokeSubject('svc-a')}"
