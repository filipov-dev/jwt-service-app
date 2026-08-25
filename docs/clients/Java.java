/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * <p>Dependencies: {@code com.eatthepath:java-otp}, {@code commons-codec}.
 *
 * <p>Env:
 * <ul>
 *   <li>{@code AUTH_TOTP_SECRET} — shared TOTP secret, base32 (required);
 *   <li>{@code JWT_SERVICE_URL} — base URL, default {@code http://localhost:8080}.
 * </ul>
 *
 * <p><b>The code is recomputed before every request.</b> With replay protection
 * on ({@code AUTH_TOTP_REPLAY_PROTECTION}) the server rejects a code it has
 * already seen with {@code 401}, even while that code is still inside its time
 * window.
 */

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

public final class Java {

    /**
     * Sent as the Host header and becomes the {@code iss} claim. Must be the
     * same on issue and on verify, or the token will not verify.
     */
    private static final String ISSUER_HOST = "example.com";

    private final String baseUrl;
    private final SecretKeySpec key;
    private final TimeBasedOneTimePasswordGenerator totp;
    private final HttpClient http = HttpClient.newHttpClient();

    /**
     * Creates a client.
     *
     * @param baseUrl service base URL
     * @param secret  shared TOTP secret, base32
     * @throws Exception if HMAC is unavailable
     */
    public Java(String baseUrl, String secret) throws Exception {
        this.baseUrl = baseUrl;
        this.key = new SecretKeySpec(new Base32().decode(secret), "HmacSHA1");
        // Service defaults: SHA-1, 6 digits, 30-second step.
        this.totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6);
    }

    /**
     * Builds a client from the environment.
     *
     * @return the client
     * @throws Exception if the secret is missing or HMAC is unavailable
     */
    public static Java fromEnv() throws Exception {
        String service = System.getenv().getOrDefault("JWT_SERVICE_URL", "http://localhost:8080");
        String secret = System.getenv("AUTH_TOTP_SECRET");

        if (secret == null) {
            throw new IllegalStateException("AUTH_TOTP_SECRET is required");
        }

        return new Java(service, secret);
    }

    /**
     * Fresh code for right now: SHA-1, 6 digits, 30-second step.
     *
     * @return six decimal digits
     * @throws Exception on HMAC failure
     */
    private String totpCode() throws Exception {
        return String.format("%06d", totp.generateOneTimePassword(key, Instant.now()));
    }

    /**
     * Sends a level 3 request.
     *
     * @param method HTTP method
     * @param path   endpoint path
     * @param body   request body, or {@code null} when there is none
     * @return the service reply
     * @throws Exception on network or HMAC failure
     */
    private HttpResponse<String> request(String method, String path, String body) throws Exception {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);

        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                // Computed here rather than reused: one code, one request.
                .header("X-TOTP-Code", totpCode())
                .header("Host", ISSUER_HOST)
                .header("Content-Type", "application/json")
                .method(method, publisher)
                .build();

        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Issues an access token ({@code POST /tokens}).
     *
     * @param sub         subject the token is issued to ({@code sub} claim)
     * @param aud         audience ({@code aud} claim)
     * @param withRefresh also return a refresh token for extending the session
     * @param claimsJson  custom claims as a JSON object (for example
     *                    {@code {"role":"admin"}}) or {@code null}. They sit
     *                    next to the registered ones, so the consumer reads
     *                    {@code role}, not {@code extra.role}; reserved names
     *                    ({@code iss}, {@code sub}, {@code aud}, {@code exp},
     *                    {@code iat}, {@code nbf}, {@code jti}) give
     *                    {@code 422} — change lifetime through {@code ttl}
     * @return response body: {@code {"token": ..., "refresh_token": ...}}
     * @throws Exception {@code 401} bad code, {@code 422} bad parameters or
     *                   forbidden claim, {@code 500} JWKS or Redis unavailable
     */
    public String issueToken(String sub, String aud, boolean withRefresh, String claimsJson)
            throws Exception {
        String claimsPart = claimsJson == null ? "" : ",\"claims\":" + claimsJson;
        String body = """
                {"sub":"%s","aud":["%s"],"refresh":%b%s}"""
                .formatted(sub, aud, withRefresh, claimsPart);

        HttpResponse<String> response = request("POST", "/tokens", body);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("issue failed: " + response.statusCode());
        }

        return response.body();
    }

    /**
     * Exchanges a refresh token for a new pair ({@code POST /tokens/refresh}).
     *
     * <p>The old token dies on exchange: store the new one and drop the previous.
     *
     * <p><b>Never retry</b> an exchange with the old token when the reply is
     * lost. A second presentation reads as theft, and the server revokes the
     * whole family — refresh tokens and the access tokens issued from them.
     * Issue a new pair instead.
     *
     * @param refreshToken token from an issue or a previous exchange
     * @return response body with the new pair
     * @throws Exception {@code 401} — token unknown, expired or already used
     */
    public String refreshTokens(String refreshToken) throws Exception {
        String body = """
                {"refresh_token":"%s"}""".formatted(refreshToken);

        HttpResponse<String> response = request("POST", "/tokens/refresh", body);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("refresh failed: " + response.statusCode());
        }

        return response.body();
    }

    /**
     * Revokes one token by its {@code jti} ({@code DELETE /tokens/{jti}}).
     *
     * <p>Idempotent: revoking an unknown {@code jti} is success too — the
     * desired state holds either way.
     *
     * @param jti token id from the {@code jti} claim
     * @throws Exception {@code 500} — store unreachable, the token is NOT
     *                   revoked; retry
     */
    public void revokeToken(String jti) throws Exception {
        HttpResponse<String> response = request("DELETE", "/tokens/" + jti, null);
        if (response.statusCode() != 204) {
            throw new IllegalStateException("revoke failed: " + response.statusCode());
        }
    }

    /**
     * Revokes every active token of a subject.
     *
     * <p>Endpoint {@code DELETE /subjects/{sub}/tokens}. The compromise path:
     * tokens cannot be killed one by one because the caller does not know their
     * {@code jti}.
     *
     * @param sub subject whose tokens are killed
     * @return response body: {@code {"revoked": N}}; expired tokens do not count
     * @throws Exception {@code 500} — store unreachable, nothing was revoked
     */
    public String revokeSubject(String sub) throws Exception {
        HttpResponse<String> response = request("DELETE", "/subjects/" + sub + "/tokens", null);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("bulk revoke failed: " + response.statusCode());
        }

        return response.body();
    }

    /**
     * Full token lifecycle: issue, refresh, bulk revoke.
     *
     * @param args unused
     * @throws Exception on any failure
     */
    public static void main(String[] args) throws Exception {
        Java client = Java.fromEnv();

        String issued = client.issueToken("svc-a", "svc-b", true, "{\"role\":\"admin\"}");
        System.out.println("issued: " + issued);

        // Real code should parse the JSON with a library instead.
        String refreshToken = issued.replaceAll(".*\"refresh_token\":\"([^\"]+)\".*", "$1");

        System.out.println("refreshed: " + client.refreshTokens(refreshToken));
        System.out.println("bulk revoke: " + client.revokeSubject("svc-a"));
    }
}
