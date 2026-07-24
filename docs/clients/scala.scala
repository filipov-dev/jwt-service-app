// Scala — библиотека: com.github.cb372:scala-otp или java-otp; здесь java-otp + sttp
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator
import org.apache.commons.codec.binary.Base32
import javax.crypto.spec.SecretKeySpec
import java.time.Instant
import sttp.client4.*

@main def run(): Unit =
  val key = Base32().decode(sys.env("AUTH_TOTP_SECRET"))                 // base32
  val service = sys.env.getOrElse("JWT_SERVICE_URL", "http://localhost:8080")

  val totp = TimeBasedOneTimePasswordGenerator()                        // SHA-1, 6, 30с
  val code = totp.generateOneTimePasswordString(SecretKeySpec(key, "HmacSHA1"), Instant.now())

  val resp = quickRequest
    .post(uri"$service/tokens")
    .header("X-TOTP-Code", code).header("Host", "example.com")
    .header("Content-Type", "application/json")
    .body("""{"sub":"svc-a","aud":["svc-b"]}""")
    .send(DefaultSyncBackend())
  println(resp.code)
