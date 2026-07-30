/**
 * Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
 * токена и массовый отзыв токенов субъекта.
 *
 * Зависимости: `dev.turingcomplete:kotlin-onetimepassword`, `commons-codec`.
 *
 * Окружение:
 * - `AUTH_TOTP_SECRET` — общий TOTP-секрет в base32 (обязательно);
 * - `JWT_SERVICE_URL` — базовый URL сервиса, по умолчанию `http://localhost:8080`.
 *
 * **Код считается заново перед каждым запросом.** При включённой на сервере
 * защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление
 * того же кода вернёт `401`, хотя сам код ещё не истёк.
 */

import dev.turingcomplete.kotlinonetimepassword.HmacAlgorithm
import dev.turingcomplete.kotlinonetimepassword.TimeBasedOneTimePasswordConfig
import dev.turingcomplete.kotlinonetimepassword.TimeBasedOneTimePasswordGenerator
import org.apache.commons.codec.binary.Base32
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.TimeUnit

/**
 * Клиент сервиса выдачи токенов.
 *
 * @property baseUrl базовый URL сервиса
 * @param secret общий TOTP-секрет в base32
 */
class JwtServiceClient(private val baseUrl: String, secret: String) {

    private companion object {
        /** Значение claim `iss`. Должно совпадать при выпуске и проверке токена. */
        const val ISSUER_HOST = "example.com"
    }

    private val http: HttpClient = HttpClient.newHttpClient()

    // Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
    private val totp = TimeBasedOneTimePasswordGenerator(
        Base32().decode(secret),
        TimeBasedOneTimePasswordConfig(30, TimeUnit.SECONDS, 6, HmacAlgorithm.SHA1),
    )

    /**
     * Вычисляет TOTP-код на текущий момент.
     *
     * @return код из шести десятичных знаков
     */
    private fun totpCode(): String = totp.generate()

    /**
     * Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
     *
     * @param method HTTP-метод
     * @param path путь ручки, начиная со слеша
     * @param body тело запроса либо `null`, если тела нет
     * @return ответ сервиса
     */
    private fun request(method: String, path: String, body: String?): HttpResponse<String> {
        val publisher = body
            ?.let { HttpRequest.BodyPublishers.ofString(it) }
            ?: HttpRequest.BodyPublishers.noBody()

        val request = HttpRequest.newBuilder(URI.create(baseUrl + path))
            // Код считается здесь, а не переиспользуется: один код — один запрос.
            .header("X-TOTP-Code", totpCode())
            .header("Host", ISSUER_HOST)
            .header("Content-Type", "application/json")
            .method(method, publisher)
            .build()

        return http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    /**
     * Выпускает access-токен (`POST /tokens`).
     *
     * @param sub субъект, которому выдаётся токен (claim `sub`)
     * @param aud получатель (claim `aud`)
     * @param withRefresh запросить refresh-токен для продления сессии
     * @param claimsJson произвольные claims JSON-объектом (например
     *   `{"role":"admin"}`) либо `null`. Попадают в payload рядом с
     *   зарегистрированными; служебные имена (`iss`, `sub`, `aud`, `exp`, `iat`,
     *   `nbf`, `jti`) переопределять нельзя — сервис ответит `422`
     * @return тело ответа: `{"token": ..., "refresh_token": ...}`
     * @throws IllegalStateException `401` — неверный код, `422` — параметры или
     *   запрещённый claim, `500` — недоступны JWKS или Redis
     */
    fun issueToken(
        sub: String,
        aud: String,
        withRefresh: Boolean = false,
        claimsJson: String? = null,
    ): String {
        val claimsPart = claimsJson?.let { ",\"claims\":$it" } ?: ""
        val body = """{"sub":"$sub","aud":["$aud"],"refresh":$withRefresh$claimsPart}"""
        val response = request("POST", "/tokens", body)

        check(response.statusCode() == 200) { "выпуск не удался: ${response.statusCode()}" }
        return response.body()
    }

    /**
     * Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
     *
     * Старый токен после обмена недействителен: сохраните новый и выбросьте
     * предыдущий.
     *
     * **Внимание:** не повторяйте обмен старым токеном при потере ответа.
     * Повторное предъявление трактуется как кража и гасит всю семью — и
     * refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
     * заново.
     *
     * @param refreshToken токен из выпуска или прошлого обмена
     * @return тело ответа с новой парой
     * @throws IllegalStateException `401` — токен неизвестен, истёк или использован
     */
    fun refreshTokens(refreshToken: String): String {
        val response = request("POST", "/tokens/refresh", """{"refresh_token":"$refreshToken"}""")

        check(response.statusCode() == 200) { "обмен не удался: ${response.statusCode()}" }
        return response.body()
    }

    /**
     * Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
     *
     * Идемпотентно: отзыв несуществующего `jti` — тоже успех.
     *
     * @param jti идентификатор токена из claim `jti`
     * @throws IllegalStateException `500` — хранилище недоступно, отзыв НЕ выполнен
     */
    fun revokeToken(jti: String) {
        val response = request("DELETE", "/tokens/$jti", null)
        check(response.statusCode() == 204) { "отзыв не удался: ${response.statusCode()}" }
    }

    /**
     * Отзывает все активные токены субъекта.
     *
     * Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить
     * токены по одному нельзя, их `jti` вызывающему неизвестны.
     *
     * @param sub субъект, чьи токены гасятся
     * @return тело ответа `{"revoked": N}`; истёкшие токены не считаются
     * @throws IllegalStateException `500` — хранилище недоступно, отзыв не выполнен
     */
    fun revokeSubject(sub: String): String {
        val response = request("DELETE", "/subjects/$sub/tokens", null)

        check(response.statusCode() == 200) { "массовый отзыв не удался: ${response.statusCode()}" }
        return response.body()
    }
}

/** Демонстрирует полный жизненный цикл токена. */
fun main() {
    val service = System.getenv("JWT_SERVICE_URL") ?: "http://localhost:8080"
    val secret = requireNotNull(System.getenv("AUTH_TOTP_SECRET")) { "нужен AUTH_TOTP_SECRET" }

    val client = JwtServiceClient(service, secret)

    val issued = client.issueToken("svc-a", "svc-b", withRefresh = true, claimsJson = """{"role":"admin"}""")
    println("выпущен: $issued")

    // В боевом коде разберите JSON библиотекой, а не регуляркой.
    val refreshToken = Regex("\"refresh_token\":\"([^\"]+)\"").find(issued)!!.groupValues[1]

    println("обновлён: ${client.refreshTokens(refreshToken)}")
    println("массовый отзыв: ${client.revokeSubject("svc-a")}")
}
