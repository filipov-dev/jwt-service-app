/** jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
  *
  * Dependencies: `com.eatthepath:java-otp`,
  * `com.softwaremill.sttp.client3::core`, `commons-codec`.
  *
  * Env:
  *   - `AUTH_TOTP_SECRET` — shared TOTP secret, base32 (required);
  *   - `JWT_SERVICE_URL` — base URL, default `http://localhost:8080`.
  *
  * '''The code is recomputed before every request.''' With replay protection on
  * (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already seen
  * with `401`, even while that code is still inside its time window.
  */

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator
import org.apache.commons.codec.binary.Base32
import sttp.client3.*

import java.time.{Duration, Instant}
import javax.crypto.spec.SecretKeySpec

/** Client of the token service, covering all four level 3 endpoints.
  *
  * @param baseUrl
  *   service base URL
  * @param secret
  *   shared TOTP secret, base32
  */
class JwtServiceClient(baseUrl: String, secret: String):

  /** Sent as the Host header and becomes the `iss` claim. Must be the same on
    * issue and on verify, or the token will not verify.
    */
  private val IssuerHost = "example.com"

  private val backend = HttpClientSyncBackend()
  private val key = SecretKeySpec(Base32().decode(secret), "HmacSHA1")

  // Service defaults: SHA-1, 6 digits, 30-second step.
  private val totp = TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6)

  /** Fresh code for right now.
    *
    * @return
    *   six decimal digits
    */
  private def totpCode(): String =
    f"${totp.generateOneTimePassword(key, Instant.now())}%06d"

  /** Sends a level 3 request.
    *
    * @param request
    *   request without the auth headers
    * @return
    *   the service reply
    */
  private def send(request: RequestT[Identity, Either[String, String], Any]) =
    request
      // Computed here rather than reused: one code, one request.
      .header("X-TOTP-Code", totpCode())
      .header("Host", IssuerHost)
      .contentType("application/json")
      .send(backend)

  /** Issues an access token (`POST /tokens`).
    *
    * @param sub
    *   subject the token is issued to (`sub` claim)
    * @param aud
    *   audience (`aud` claim)
    * @param withRefresh
    *   also return a refresh token for extending the session
    * @param claimsJson
    *   custom claims as a JSON object (for example `{"role":"admin"}`) or
    *   `None`. They sit next to the registered ones, so the consumer reads
    *   `role`, not `extra.role`; reserved names (`iss`, `sub`, `aud`, `exp`,
    *   `iat`, `nbf`, `jti`) give `422` — change lifetime through `ttl`
    * @return
    *   response body: `{"token": ..., "refresh_token": ...}`
    * @throws IllegalStateException
    *   `401` bad code, `422` bad parameters or forbidden claim, `500` JWKS or
    *   Redis unavailable
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

  /** Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
    *
    * The old token dies on exchange: store the new one and drop the previous.
    *
    * '''Never retry''' an exchange with the old token when the reply is lost. A
    * second presentation reads as theft, and the server revokes the whole
    * family — refresh tokens and the access tokens issued from them. Issue a
    * new pair instead.
    *
    * @param refreshToken
    *   token from an issue or a previous exchange
    * @return
    *   response body with the new pair
    * @throws IllegalStateException
    *   `401` — token unknown, expired or already used
    */
  def refreshTokens(refreshToken: String): String =
    val body = s"""{"refresh_token":"$refreshToken"}"""
    val response = send(basicRequest.post(uri"$baseUrl/tokens/refresh").body(body))

    response.body.fold(
      error => throw IllegalStateException(s"refresh failed: $error"),
      identity,
    )

  /** Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
    *
    * Idempotent: revoking an unknown `jti` is success too — the desired state
    * holds either way.
    *
    * @param jti
    *   token id from the `jti` claim
    * @throws IllegalStateException
    *   `500` — store unreachable, the token is NOT revoked; retry
    */
  def revokeToken(jti: String): Unit =
    val response = send(basicRequest.delete(uri"$baseUrl/tokens/$jti"))

    if response.code.code != 204 then
      throw IllegalStateException(s"revoke failed: ${response.code}")

  /** Revokes every active token of a subject.
    *
    * Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens
    * cannot be killed one by one because the caller does not know their `jti`.
    *
    * @param sub
    *   subject whose tokens are killed
    * @return
    *   response body `{"revoked": N}`; expired tokens do not count
    * @throws IllegalStateException
    *   `500` — store unreachable, nothing was revoked
    */
  def revokeSubject(sub: String): String =
    val response = send(basicRequest.delete(uri"$baseUrl/subjects/$sub/tokens"))

    response.body.fold(
      error => throw IllegalStateException(s"bulk revoke failed: $error"),
      identity,
    )

/** Full token lifecycle: issue, refresh, bulk revoke. */
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
