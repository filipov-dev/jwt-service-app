/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Dependencies: `dev.turingcomplete:kotlin-onetimepassword`, `commons-codec`.
 * Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
 * `http://localhost:8080`).
 * See README.md for endpoints, error codes and client rules.
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
 * Client of the token service.
 *
 * @property baseUrl service base URL
 * @param secret shared TOTP secret, base32
 */
class JwtServiceClient(private val baseUrl: String, secret: String) {

    private companion object {
        /** Sent as the Host header, becomes the `iss` claim. */
        const val ISSUER_HOST = "example.com"
    }

    private val http: HttpClient = HttpClient.newHttpClient()

    // Service defaults: SHA-1, 6 digits, 30-second step.
    private val totp = TimeBasedOneTimePasswordGenerator(
        Base32().decode(secret),
        TimeBasedOneTimePasswordConfig(30, TimeUnit.SECONDS, 6, HmacAlgorithm.SHA1),
    )

    /** Fresh TOTP code, computed right before each call. */
    private fun totpCode(): String = totp.generate()

    /**
     * Sends a level 3 request with a fresh code.
     *
     * @param method HTTP method
     * @param path endpoint path
     * @param body request body, or `null`
     * @return service reply
     */
    private fun request(method: String, path: String, body: String?): HttpResponse<String> {
        val publisher = body
            ?.let { HttpRequest.BodyPublishers.ofString(it) }
            ?: HttpRequest.BodyPublishers.noBody()

        val request = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .header("X-TOTP-Code", totpCode())
            .header("Host", ISSUER_HOST)
            .header("Content-Type", "application/json")
            .method(method, publisher)
            .build()

        return http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    /**
     * `POST /tokens`
     *
     * @param sub subject
     * @param aud audience
     * @param withRefresh also ask for a refresh token
     * @param claimsJson custom claims as a JSON object, or `null`
     * @return response body: `{"token": ..., "refresh_token": ...}`
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
     * `POST /tokens/refresh` — returns a new pair; the old refresh token is dead
     * once the call succeeds.
     *
     * @param refreshToken token from an issue or a previous refresh
     * @return response body with the new pair
     */
    fun refreshTokens(refreshToken: String): String {
        val response = request("POST", "/tokens/refresh", """{"refresh_token":"$refreshToken"}""")

        check(response.statusCode() == 200) { "refresh failed: ${response.statusCode()}" }
        return response.body()
    }

    /**
     * `DELETE /tokens/{jti}` — idempotent.
     *
     * @param jti token id from the `jti` claim
     */
    fun revokeToken(jti: String) {
        val response = request("DELETE", "/tokens/$jti", null)
        check(response.statusCode() == 204) { "revoke failed: ${response.statusCode()}" }
    }

    /**
     * `DELETE /subjects/{sub}/tokens`
     *
     * @param sub subject whose tokens are revoked
     * @return response body: `{"revoked": N}`
     */
    fun revokeSubject(sub: String): String {
        val response = request("DELETE", "/subjects/$sub/tokens", null)

        check(response.statusCode() == 200) { "bulk revoke failed: ${response.statusCode()}" }
        return response.body()
    }
}

/** Issue -> refresh -> revoke. */
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
