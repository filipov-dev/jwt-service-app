// Groovy — библиотека: java-otp (Grab) + java.net.http
@Grab('com.eatthepath:java-otp:0.4.0')
@Grab('commons-codec:commons-codec:1.16.0')
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator
import org.apache.commons.codec.binary.Base32
import javax.crypto.spec.SecretKeySpec
import java.time.Instant
import java.net.http.*

def key = new Base32().decode(System.getenv('AUTH_TOTP_SECRET'))          // base32
def service = System.getenv('JWT_SERVICE_URL') ?: 'http://localhost:8080'

def code = new TimeBasedOneTimePasswordGenerator()
        .generateOneTimePasswordString(new SecretKeySpec(key, 'HmacSHA1'), Instant.now())

def resp = HttpClient.newHttpClient().send(
    HttpRequest.newBuilder(URI.create("$service/tokens"))
        .header('X-TOTP-Code', code).header('Host', 'example.com')
        .header('Content-Type', 'application/json')
        .POST(HttpRequest.BodyPublishers.ofString('{"sub":"svc-a","aud":["svc-b"]}'))
        .build(), HttpResponse.BodyHandlers.ofString())
println "${resp.statusCode()} ${resp.body()}"
