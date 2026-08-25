/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Dependencies: `dev.turingcomplete:kotlin-onetimepassword`, `commons-codec`.
 *
 * Env:
 * - `AUTH_TOTP_SECRET` — shared TOTP secret, base32 (required);
 * - `JWT_SERVICE_URL` — service base URL, default `http://localhost:8080`.
 *
 * **The code is recomputed before every request.** With replay protection on
 * (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already seen
 * with `401`, even while that code is still inside its time window.
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
 * Client of the token service, covering all four level 3 endpoints.
 *
 * @property baseUrl service base URL
 * @param secret shared TOTP secret, base32
 */
class JwtServiceClient(private val baseUrl: String, secret: String) {

    private companion object {
        /**
         * Sent as the Host header and becomes the `iss` claim. Must be the same
         * on issue and on verify, or the token will not verify.
         */
        const val ISSUER_HOST = "example.com"
    }

    private val http: HttpClient = HttpClient.newHttpClient()

    // Service defaults: SHA-1, 6 digits, 30-second step.
    private val totp = TimeBasedOneTimePasswordGenerator(
        Base32().decode(secret),
        TimeBasedOneTimePasswordConfig(30, TimeUnit.SECONDS, 6, HmacAlgorithm.SHA1),
    )

    /**
     * Fresh code for right now.
     *
     * @return six decimal digits
     */
    private fun totpCode(): String = totp.generate()

    /**
     * Sends a level 3 request.
     *
     * @param method HTTP method
     * @param path endpoint path
     * @param body request body, or `null` when there is none
     * @return the service reply
     */
    private fun request(method: String, path: String, body: String?): HttpResponse<String> {
        val publisher = body
            ?.let { HttpRequest.BodyPublishers.ofString(it) }
            ?: HttpRequest.BodyPublishers.noBody()

        val request = HttpRequest.newBuilder(URI.create(baseUrl + path))
            // Computed here rather than reused: one code, one request.
            .header("X-TOTP-Code", totpCode())
            .header("Host", ISSUER_HOST)
            .header("Content-Type", "application/json")
            .method(method, publisher)
            .build()

        return http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    /**
     * Issues an access token (`POST /tokens`).
     *
     * @param sub subject the token is issued to (`sub` claim)
     * @param aud audience (`aud` claim)
     * @param withRefresh also return a refresh token for extending the session
     * @param claimsJson custom claims as a JSON object (for example
     *   `{"role":"admin"}`) or `null`. They sit next to the registered ones, so
     *   the consumer reads `role`, not `extra.role`; reserved names (`iss`,
     *   `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) give `422` — change lifetime
     *   through `ttl`, not `exp`
     * @return response body: `{"token": ..., "refresh_token": ...}`
     * @throws IllegalStateException `401` bad code, `422` bad parameters or
     *   forbidden claim, `500` JWKS or Redis unavailable
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

        check(response.statusCode() == 200) { "issue failed: ${response.statusCode()}" }
        return response.body()
    }

    /**
     * Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
     *
     * The old token dies on exchange: store the new one and drop the previous.
     *
     * **Never retry** an exchange with the old token when the reply is lost. A
     * second presentation reads as theft, and the server revokes the whole
     * family — refresh tokens and the access tokens issued from them. Issue a
     * new pair instead.
     *
     * @param refreshToken token from an issue or a previous exchange
     * @return response body with the new pair
     * @throws IllegalStateException `401` — token unknown, expired or already used
     */
    fun refreshTokens(refreshToken: String): String {
        val response = request("POST", "/tokens/refresh", """{"refresh_token":"$refreshToken"}""")

        check(response.statusCode() == 200) { "refresh failed: ${response.statusCode()}" }
        return response.body()
    }

    /**
     * Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
     *
     * Idempotent: revoking an unknown `jti` is success too — the desired state
     * holds either way.
     *
     * @param jti token id from the `jti` claim
     * @throws IllegalStateException `500` — store unreachable, the token is NOT
     *   revoked; retry
     */
    fun revokeToken(jti: String) {
        val response = request("DELETE", "/tokens/$jti", null)
        check(response.statusCode() == 204) { "revoke failed: ${response.statusCode()}" }
    }

    /**
     * Revokes every active token of a subject.
     *
     * Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens
     * cannot be killed one by one because the caller does not know their `jti`.
     *
     * @param sub subject whose tokens are killed
     * @return response body `{"revoked": N}`; expired tokens do not count
     * @throws IllegalStateException `500` — store unreachable, nothing was revoked
     */
    fun revokeSubject(sub: String): String {
        val response = request("DELETE", "/subjects/$sub/tokens", null)

        check(response.statusCode() == 200) { "bulk revoke failed: ${response.statusCode()}" }
        return response.body()
    }
}

/** Full token lifecycle: issue, refresh, bulk revoke. */
fun main() {
    val service = System.getenv("JWT_SERVICE_URL") ?: "http://localhost:8080"
    val secret = requireNotNull(System.getenv("AUTH_TOTP_SECRET")) { "AUTH_TOTP_SECRET is required" }

    val client = JwtServiceClient(service, secret)

    val issued = client.issueToken("svc-a", "svc-b", withRefresh = true, claimsJson = """{"role":"admin"}""")
    println("issued: $issued")

    // Real code should parse the JSON with a library, not a regex.
    val refreshToken = Regex("\"refresh_token\":\"([^\"]+)\"").find(issued)!!.groupValues[1]

    println("refreshed: ${client.refreshTokens(refreshToken)}")
    println("bulk revoke: ${client.revokeSubject("svc-a")}")
}
