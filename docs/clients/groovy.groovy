/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Dependencies are pulled in with {@code @Grab}.
 *
 * Env: {@code AUTH_TOTP_SECRET} (base32), {@code JWT_SERVICE_URL} (default
 * {@code http://localhost:8080}).
 *
 * See README.md for endpoints, error codes and client rules.
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
 * Client of the token service.
 */
class JwtServiceClient {

    /** Sent as the Host header, becomes the {@code iss} claim. */
    static final String ISSUER_HOST = 'example.com'

    private final String baseUrl
    private final SecretKeySpec key
    private final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator()
    private final HttpClient http = HttpClient.newHttpClient()

    /**
     * Creates a client.
     *
     * @param baseUrl service base URL
     * @param secret shared TOTP secret, base32
     */
    JwtServiceClient(String baseUrl, String secret) {
        this.baseUrl = baseUrl
        this.key = new SecretKeySpec(new Base32().decode(secret), 'HmacSHA1')
    }

    /**
     * Builds a client from the environment.
     *
     * @return the client
     */
    static JwtServiceClient fromEnv() {
        def secret = System.getenv('AUTH_TOTP_SECRET')
        assert secret != null, 'AUTH_TOTP_SECRET is required'

        new JwtServiceClient(System.getenv('JWT_SERVICE_URL') ?: 'http://localhost:8080', secret)
    }

    /**
     * Fresh TOTP code: SHA-1, 6 digits, 30-second step.
     *
     * @return six decimal digits
     */
    private String totpCode() {
        totp.generateOneTimePasswordString(key, Instant.now())
    }

    /**
     * Sends a level 3 request with a code computed right before the call.
     *
     * @param method HTTP method
     * @param path endpoint path
     * @param body request body, or {@code null}
     * @return service reply
     */
    private HttpResponse<String> request(String method, String path, String body) {
        def publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body)

        def request = HttpRequest.newBuilder(URI.create("$baseUrl$path"))
                .header('X-TOTP-Code', totpCode())
                .header('Host', ISSUER_HOST)
                .header('Content-Type', 'application/json')
                .method(method, publisher)
                .build()

        http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    /**
     * {@code POST /tokens}
     *
     * @param sub subject
     * @param aud audience
     * @param withRefresh also ask for a refresh token
     * @param claims custom claims
     * @return parsed reply with {@code token} and, if requested,
     *         {@code refresh_token}
     */
    Map issueToken(String sub, List<String> aud, boolean withRefresh = false, Map claims = [:]) {
        def payload = [sub: sub, aud: aud, refresh: withRefresh]
        if (claims) payload.claims = claims

        def body = JsonOutput.toJson(payload)
        def response = request('POST', '/tokens', body)

        if (response.statusCode() != 200) {
            throw new IllegalStateException("issue failed: ${response.statusCode()}")
        }

        new JsonSlurper().parseText(response.body()) as Map
    }

    /**
     * {@code POST /tokens/refresh} — returns a new pair; the old refresh token
     * is dead once the call succeeds.
     *
     * @param refreshToken token from an issue or a previous refresh
     * @return the new access + refresh pair
     */
    Map refreshTokens(String refreshToken) {
        def body = JsonOutput.toJson([refresh_token: refreshToken])
        def response = request('POST', '/tokens/refresh', body)

        if (response.statusCode() != 200) {
            throw new IllegalStateException("refresh failed: ${response.statusCode()}")
        }

        new JsonSlurper().parseText(response.body()) as Map
    }

    /**
     * {@code DELETE /tokens/{jti}} — idempotent.
     *
     * @param jti token id from the {@code jti} claim
     */
    void revokeToken(String jti) {
        def response = request('DELETE', "/tokens/$jti", null)

        if (response.statusCode() != 204) {
            throw new IllegalStateException("revoke failed: ${response.statusCode()}")
        }
    }

    /**
     * {@code DELETE /subjects/{sub}/tokens}
     *
     * @param sub subject whose tokens are revoked
     * @return number of revoked tokens
     */
    int revokeSubject(String sub) {
        def response = request('DELETE', "/subjects/$sub/tokens", null)

        if (response.statusCode() != 200) {
            throw new IllegalStateException("bulk revoke failed: ${response.statusCode()}")
        }

        (new JsonSlurper().parseText(response.body()) as Map).revoked as int
    }
}

// Issue -> refresh -> revoke.
def client = JwtServiceClient.fromEnv()

def issued = client.issueToken('svc-a', ['svc-b'], true, [role: 'admin'])
println "issued: ${issued.token.take(32)}..."

def refreshed = client.refreshTokens(issued.refresh_token as String)
println "refreshed: ${refreshed.token.take(32)}..."

println "revoked: ${client.revokeSubject('svc-a')}"
