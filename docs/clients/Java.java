/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * <p>Dependencies: {@code com.eatthepath:java-otp}, {@code commons-codec}.
 *
 * <p>Env: {@code AUTH_TOTP_SECRET} (base32), {@code JWT_SERVICE_URL} (default
 * {@code http://localhost:8080}).
 *
 * <p>See README.md for endpoints, error codes and client rules.
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

    /** Sent as the Host header, becomes the {@code iss} claim. */
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
     * Fresh TOTP code: SHA-1, 6 digits, 30-second step.
     *
     * @return six decimal digits
     * @throws Exception on HMAC failure
     */
    private String totpCode() throws Exception {
        return String.format("%06d", totp.generateOneTimePassword(key, Instant.now()));
    }

    /**
     * Sends a level 3 request with a code computed right before the call.
     *
     * @param method HTTP method
     * @param path   endpoint path
     * @param body   request body, or {@code null}
     * @return service reply
     * @throws Exception on network or HMAC failure
     */
    private HttpResponse<String> request(String method, String path, String body) throws Exception {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);

        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("X-TOTP-Code", totpCode())
                .header("Host", ISSUER_HOST)
                .header("Content-Type", "application/json")
                .method(method, publisher)
                .build();

        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * {@code POST /tokens}
     *
     * @param sub         subject
     * @param aud         audience
     * @param withRefresh also ask for a refresh token
     * @param claimsJson  custom claims as a JSON object, or {@code null}
     * @return response body: {@code {"token": ..., "refresh_token": ...}}
     * @throws Exception on a non-200 reply
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
     * {@code POST /tokens/refresh} — returns a new pair; the old refresh token
     * is dead once the call succeeds.
     *
     * @param refreshToken token from an issue or a previous refresh
     * @return response body with the new pair
     * @throws Exception on a non-200 reply
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
     * {@code DELETE /tokens/{jti}} — idempotent.
     *
     * @param jti token id from the {@code jti} claim
     * @throws Exception on a non-204 reply
     */
    public void revokeToken(String jti) throws Exception {
        HttpResponse<String> response = request("DELETE", "/tokens/" + jti, null);
        if (response.statusCode() != 204) {
            throw new IllegalStateException("revoke failed: " + response.statusCode());
        }
    }

    /**
     * {@code DELETE /subjects/{sub}/tokens}
     *
     * @param sub subject whose tokens are revoked
     * @return response body: {@code {"revoked": N}}
     * @throws Exception on a non-200 reply
     */
    public String revokeSubject(String sub) throws Exception {
        HttpResponse<String> response = request("DELETE", "/subjects/" + sub + "/tokens", null);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("bulk revoke failed: " + response.statusCode());
        }

        return response.body();
    }

    /**
     * Issue -&gt; refresh -&gt; revoke.
     *
     * @param args unused
     * @throws Exception on any failure
     */
    public static void main(String[] args) throws Exception {
        Java client = Java.fromEnv();

        String issued = client.issueToken("svc-a", "svc-b", true, "{\"role\":\"admin\"}");
        System.out.println("issued: " + issued);

        // Real code should parse the JSON with a library.
        String refreshToken = issued.replaceAll(".*\"refresh_token\":\"([^\"]+)\".*", "$1");

        System.out.println("refreshed: " + client.refreshTokens(refreshToken));
        System.out.println("bulk revoke: " + client.revokeSubject("svc-a"));
    }
}
