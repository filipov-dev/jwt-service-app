// Java — библиотека: java-otp (com.eatthepath:java-otp) + java.net.http
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.*;
import java.time.Instant;

public class Java {
    public static void main(String[] args) throws Exception {
        byte[] key = new Base32().decode(System.getenv("AUTH_TOTP_SECRET")); // base32
        String service = System.getenv().getOrDefault("JWT_SERVICE_URL", "http://localhost:8080");

        var totp = new TimeBasedOneTimePasswordGenerator();                  // SHA-1, 6, 30с
        String code = totp.generateOneTimePasswordString(
                new SecretKeySpec(key, "HmacSHA1"), Instant.now());

        HttpResponse<String> resp = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create(service + "/tokens"))
                .header("X-TOTP-Code", code).header("Host", "example.com")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"sub\":\"svc-a\",\"aud\":[\"svc-b\"]}"))
                .build(), HttpResponse.BodyHandlers.ofString());
        System.out.println(resp.statusCode() + " " + resp.body());
    }
}
