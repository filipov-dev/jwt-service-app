/** Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
  *
  * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
  * токена и массовый отзыв токенов субъекта.
  *
  * Зависимости: `com.eatthepath:java-otp`, `com.softwaremill.sttp.client3::core`,
  * `commons-codec`.
  *
  * Окружение:
  *   - `AUTH_TOTP_SECRET` — общий TOTP-секрет в base32 (обязательно);
  *   - `JWT_SERVICE_URL` — базовый URL, по умолчанию `http://localhost:8080`.
  *
  * '''Код считается заново перед каждым запросом.''' При включённой на сервере
  * защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное
  * предъявление того же кода вернёт `401`, хотя сам код ещё не истёк.
  */

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator
import org.apache.commons.codec.binary.Base32
import sttp.client3.*

import java.time.{Duration, Instant}
import javax.crypto.spec.SecretKeySpec

/** Клиент сервиса выдачи токенов.
  *
  * @param baseUrl
  *   базовый URL сервиса
  * @param secret
  *   общий TOTP-секрет в base32
  */
class JwtServiceClient(baseUrl: String, secret: String):

  /** Значение claim `iss`. Должно совпадать при выпуске и проверке токена. */
  private val IssuerHost = "example.com"

  private val backend = HttpClientSyncBackend()
  private val key = SecretKeySpec(Base32().decode(secret), "HmacSHA1")

  // Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
  private val totp = TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6)

  /** Вычисляет TOTP-код на текущий момент.
    *
    * @return
    *   код из шести десятичных знаков
    */
  private def totpCode(): String =
    f"${totp.generateOneTimePassword(key, Instant.now())}%06d"

  /** Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
    *
    * @param request
    *   заготовка запроса без заголовков авторизации
    * @return
    *   ответ сервиса
    */
  private def send(request: RequestT[Identity, Either[String, String], Any]) =
    request
      // Код считается здесь, а не переиспользуется: один код — один запрос.
      .header("X-TOTP-Code", totpCode())
      .header("Host", IssuerHost)
      .contentType("application/json")
      .send(backend)

  /** Выпускает access-токен (`POST /tokens`).
    *
    * @param sub
    *   субъект, которому выдаётся токен (claim `sub`)
    * @param aud
    *   получатель (claim `aud`)
    * @param withRefresh
    *   запросить refresh-токен для продления сессии
    * @param claimsJson
    *   произвольные claims JSON-объектом (например `{"role":"admin"}`) либо
    *   `None`. Попадают в payload рядом с зарегистрированными; служебные имена
    *   (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) переопределять нельзя —
    *   сервис ответит `422`
    * @return
    *   тело ответа: `{"token": ..., "refresh_token": ...}`
    * @throws IllegalStateException
    *   `401` — неверный код, `422` — параметры или запрещённый claim,
    *   `500` — JWKS или Redis
    */
  def issueToken(
      sub: String,
      aud: String,
      withRefresh: Boolean = false,
      claimsJson: Option[String] = None,
  ): String =
    val claimsPart = claimsJson.map(c => s""","claims":$c""").getOrElse("")
    val body = s"""{"sub":"$sub","aud":["$aud"],"refresh":$withRefresh$claimsPart}"""
    val response = send(basicRequest.post(uri"$baseUrl/tokens").body(body))

    response.body.fold(
      error => throw IllegalStateException(s"выпуск не удался: $error"),
      identity,
    )

  /** Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
    *
    * Старый токен после обмена недействителен: сохраните новый и выбросьте
    * предыдущий.
    *
    * '''Внимание:''' не повторяйте обмен старым токеном при потере ответа.
    * Повторное предъявление трактуется как кража и гасит всю семью — и
    * refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
    * заново.
    *
    * @param refreshToken
    *   токен из выпуска или прошлого обмена
    * @return
    *   тело ответа с новой парой
    * @throws IllegalStateException
    *   `401` — токен неизвестен, истёк или уже использован
    */
  def refreshTokens(refreshToken: String): String =
    val body = s"""{"refresh_token":"$refreshToken"}"""
    val response = send(basicRequest.post(uri"$baseUrl/tokens/refresh").body(body))

    response.body.fold(
      error => throw IllegalStateException(s"обмен не удался: $error"),
      identity,
    )

  /** Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
    *
    * Идемпотентно: отзыв несуществующего `jti` — тоже успех.
    *
    * @param jti
    *   идентификатор токена из claim `jti`
    * @throws IllegalStateException
    *   `500` — хранилище недоступно, отзыв НЕ выполнен
    */
  def revokeToken(jti: String): Unit =
    val response = send(basicRequest.delete(uri"$baseUrl/tokens/$jti"))

    if response.code.code != 204 then
      throw IllegalStateException(s"отзыв не удался: ${response.code}")

  /** Отзывает все активные токены субъекта.
    *
    * Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить
    * токены по одному нельзя, их `jti` вызывающему неизвестны.
    *
    * @param sub
    *   субъект, чьи токены гасятся
    * @return
    *   тело ответа `{"revoked": N}`; истёкшие токены не считаются
    * @throws IllegalStateException
    *   `500` — хранилище недоступно, отзыв не выполнен
    */
  def revokeSubject(sub: String): String =
    val response = send(basicRequest.delete(uri"$baseUrl/subjects/$sub/tokens"))

    response.body.fold(
      error => throw IllegalStateException(s"массовый отзыв не удался: $error"),
      identity,
    )

/** Демонстрирует полный жизненный цикл токена. */
@main def run(): Unit =
  val service = sys.env.getOrElse("JWT_SERVICE_URL", "http://localhost:8080")
  val secret = sys.env.getOrElse("AUTH_TOTP_SECRET", sys.error("нужен AUTH_TOTP_SECRET"))

  val client = JwtServiceClient(service, secret)

  val issued = client.issueToken("svc-a", "svc-b", withRefresh = true,
    claimsJson = Some("""{"role":"admin"}"""))
  println(s"выпущен: $issued")

  // В боевом коде разберите JSON библиотекой, а не регуляркой.
  val refreshToken = """"refresh_token":"([^"]+)"""".r.findFirstMatchIn(issued).get.group(1)

  println(s"обновлён: ${client.refreshTokens(refreshToken)}")
  println(s"массовый отзыв: ${client.revokeSubject("svc-a")}")
