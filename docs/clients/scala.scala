/** jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
  *
  * Dependencies: `com.eatthepath:java-otp`,
  * `com.softwaremill.sttp.client3::core`, `commons-codec`.
  *
  * Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
  * `http://localhost:8080`).
  *
  * See README.md for endpoints, error codes and client rules.
  */

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator
import org.apache.commons.codec.binary.Base32
import sttp.client3.*

import java.time.{Duration, Instant}
import javax.crypto.spec.SecretKeySpec

/** Client of the token service.
  *
  * @param baseUrl
  *   service base URL
  * @param secret
  *   shared TOTP secret, base32
  */
class JwtServiceClient(baseUrl: String, secret: String):

  /** Sent as the Host header, becomes the `iss` claim. */
  private val IssuerHost = "example.com"

  private val backend = HttpClientSyncBackend()
  private val key = SecretKeySpec(Base32().decode(secret), "HmacSHA1")

  // Service defaults: SHA-1, 6 digits, 30-second step.
  private val totp = TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6)

  /** Fresh TOTP code, computed right before each call. */
  private def totpCode(): String =
    f"${totp.generateOneTimePassword(key, Instant.now())}%06d"

  /** Sends a level 3 request with a fresh code.
    *
    * @param request
    *   request without the auth headers
    * @return
    *   service reply
    */
  private def send(request: RequestT[Identity, Either[String, String], Any]) =
    request
      .header("X-TOTP-Code", totpCode())
      .header("Host", IssuerHost)
      .contentType("application/json")
      .send(backend)

  /** `POST /tokens`
    *
    * @param sub
    *   subject
    * @param aud
    *   audience
    * @param withRefresh
    *   also ask for a refresh token
    * @param claimsJson
    *   custom claims as a JSON object, or `None`
    * @return
    *   response body: `{"token": ..., "refresh_token": ...}`
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
      error => throw IllegalStateException(s"issue failed: $error"),
      identity,
    )

  /** `POST /tokens/refresh` — returns a new pair; the old refresh token is dead
    * once the call succeeds.
    *
    * @param refreshToken
    *   token from an issue or a previous refresh
    * @return
    *   response body with the new pair
    */
  def refreshTokens(refreshToken: String): String =
    val body = s"""{"refresh_token":"$refreshToken"}"""
    val response = send(basicRequest.post(uri"$baseUrl/tokens/refresh").body(body))

    response.body.fold(
      error => throw IllegalStateException(s"refresh failed: $error"),
      identity,
    )

  /** `DELETE /tokens/{jti}` — idempotent.
    *
    * @param jti
    *   token id from the `jti` claim
    */
  def revokeToken(jti: String): Unit =
    val response = send(basicRequest.delete(uri"$baseUrl/tokens/$jti"))

    if response.code.code != 204 then
      throw IllegalStateException(s"revoke failed: ${response.code}")

  /** `DELETE /subjects/{sub}/tokens`
    *
    * @param sub
    *   subject whose tokens are revoked
    * @return
    *   response body: `{"revoked": N}`
    */
  def revokeSubject(sub: String): String =
    val response = send(basicRequest.delete(uri"$baseUrl/subjects/$sub/tokens"))

    response.body.fold(
      error => throw IllegalStateException(s"bulk revoke failed: $error"),
      identity,
    )

/** Issue -> refresh -> revoke. */
@main def run(): Unit =
  val service = sys.env.getOrElse("JWT_SERVICE_URL", "http://localhost:8080")
  val secret = sys.env.getOrElse("AUTH_TOTP_SECRET", sys.error("AUTH_TOTP_SECRET is required"))

  val client = JwtServiceClient(service, secret)

  val issued = client.issueToken("svc-a", "svc-b", withRefresh = true,
    claimsJson = Some("""{"role":"admin"}"""))
  println(s"issued: $issued")

  // Real code should parse the JSON with a library, not a regex.
  val refreshToken = """"refresh_token":"([^"]+)"""".r.findFirstMatchIn(issued).get.group(1)

  println(s"refreshed: ${client.refreshTokens(refreshToken)}")
  println(s"bulk revoke: ${client.revokeSubject("svc-a")}")
