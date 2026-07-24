// Kotlin — библиотека: dev.turingcomplete:kotlin-onetimepassword + java.net.http
import dev.turingcomplete.kotlinonetimepassword.*
import org.apache.commons.codec.binary.Base32
import java.net.URI
import java.net.http.*

fun main() {
    val key = Base32().decode(System.getenv("AUTH_TOTP_SECRET"))          // base32
    val service = System.getenv("JWT_SERVICE_URL") ?: "http://localhost:8080"

    val config = TimeBasedOneTimePasswordConfig(30, java.util.concurrent.TimeUnit.SECONDS,
        6, HmacAlgorithm.SHA1)
    val code = TimeBasedOneTimePasswordGenerator(key, config).generate()

    val resp = HttpClient.newHttpClient().send(
        HttpRequest.newBuilder(URI.create("$service/tokens"))
            .header("X-TOTP-Code", code).header("Host", "example.com")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("""{"sub":"svc-a","aud":["svc-b"]}"""))
            .build(), HttpResponse.BodyHandlers.ofString())
    println("${resp.statusCode()} ${resp.body()}")
}
