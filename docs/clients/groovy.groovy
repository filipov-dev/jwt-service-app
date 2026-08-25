/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Dependencies are pulled in with {@code @Grab}.
 *
 * Env:
 * <ul>
 *   <li>{@code AUTH_TOTP_SECRET} — shared TOTP secret, base32 (required);</li>
 *   <li>{@code JWT_SERVICE_URL} — base URL, default {@code http://localhost:8080}.</li>
 * </ul>
 *
 * <b>The code is recomputed before every request.</b> With replay protection on
 * ({@code AUTH_TOTP_REPLAY_PROTECTION}) the server rejects a code it has already
 * seen with {@code 401}, even while that code is still inside its time window.
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
 * Client of the token service, covering all four level 3 endpoints.
 */
class JwtServiceClient {

    /**
     * Sent as the Host header and becomes the {@code iss} claim. Must be the
     * same on issue and on verify, or the token will not verify.
     */
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
     * Fresh code for right now: SHA-1, 6 digits, 30-second step.
     *
     * @return six decimal digits
     */
    private String totpCode() {
        totp.generateOneTimePasswordString(key, Instant.now())
    }

    /**
     * Sends a level 3 request.
     *
     * @param method HTTP method
     * @param path endpoint path
     * @param body request body, or {@code null} when there is none
     * @return the service reply
     */
    private HttpResponse<String> request(String method, String path, String body) {
        def publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body)

        def request = HttpRequest.newBuilder(URI.create("$baseUrl$path"))
                // Computed here rather than reused: one code, one request.
                .header('X-TOTP-Code', totpCode())
                .header('Host', ISSUER_HOST)
                .header('Content-Type', 'application/json')
                .method(method, publisher)
                .build()

        http.send(request, HttpResponse.BodyHandlers.ofString())
    }

    /**
     * Issues an access token ({@code POST /tokens}).
     *
     * @param sub subject the token is issued to ({@code sub} claim)
     * @param aud audience ({@code aud} claim); must not be empty
     * @param withRefresh also return a refresh token for extending the session
     * @param claims custom claims (role, scope, tenant) — they sit next to the
     *        registered ones, so the consumer reads {@code role}, not
     *        {@code extra.role}. Reserved names ({@code iss}, {@code sub},
     *        {@code aud}, {@code exp}, {@code iat}, {@code nbf}, {@code jti})
     *        give {@code 422} — change lifetime through {@code ttl}
     * @return parsed reply with {@code token} and, if requested,
     *         {@code refresh_token}
     * @throws IllegalStateException {@code 401} bad code, {@code 422} bad
     *         parameters or forbidden claim, {@code 500} JWKS or Redis unavailable
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
     * Exchanges a refresh token for a new pair ({@code POST /tokens/refresh}).
     *
     * The old token dies on exchange: store the new one and drop the previous.
     *
     * <b>Never retry</b> an exchange with the old token when the reply is lost.
     * A second presentation reads as theft, and the server revokes the whole
     * family — refresh tokens and the access tokens issued from them. Issue a
     * new pair instead.
     *
     * @param refreshToken token from an issue or a previous exchange
     * @return the new access + refresh pair
     * @throws IllegalStateException {@code 401} — token unknown, expired or
     *         already used
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
     * Revokes one token by its {@code jti} ({@code DELETE /tokens/{jti}}).
     *
     * Idempotent: revoking an unknown {@code jti} is success too — the desired
     * state holds either way.
     *
     * @param jti token id from the {@code jti} claim
     * @throws IllegalStateException {@code 500} — store unreachable, the token
     *         is NOT revoked: retry
     */
    void revokeToken(String jti) {
        def response = request('DELETE', "/tokens/$jti", null)

        if (response.statusCode() != 204) {
            throw new IllegalStateException("revoke failed: ${response.statusCode()}")
        }
    }

    /**
     * Revokes every active token of a subject.
     *
     * Endpoint {@code DELETE /subjects/{sub}/tokens}. The compromise path:
     * tokens cannot be killed one by one because the caller does not know their
     * {@code jti}.
     *
     * @param sub subject whose tokens are killed
     * @return number of revoked tokens; expired ones do not count
     * @throws IllegalStateException {@code 500} — store unreachable, nothing
     *         was revoked
     */
    int revokeSubject(String sub) {
        def response = request('DELETE', "/subjects/$sub/tokens", null)

        if (response.statusCode() != 200) {
            throw new IllegalStateException("bulk revoke failed: ${response.statusCode()}")
        }

        (new JsonSlurper().parseText(response.body()) as Map).revoked as int
    }
}

// Full token lifecycle: issue, refresh, bulk revoke.
def client = JwtServiceClient.fromEnv()

def issued = client.issueToken('svc-a', ['svc-b'], true, [role: 'admin'])
println "issued: ${issued.token.take(32)}..."

def refreshed = client.refreshTokens(issued.refresh_token as String)
println "refreshed: ${refreshed.token.take(32)}..."

println "revoked: ${client.revokeSubject('svc-a')}"
