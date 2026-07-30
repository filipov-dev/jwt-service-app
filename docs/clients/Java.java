/**
 * Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * <p>Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв
 * одного токена и массовый отзыв токенов субъекта.
 *
 * <p>Зависимости: {@code com.eatthepath:java-otp}, {@code commons-codec}.
 *
 * <p>Окружение:
 * <ul>
 *   <li>{@code AUTH_TOTP_SECRET} — общий TOTP-секрет в base32 (обязательно);
 *   <li>{@code JWT_SERVICE_URL} — базовый URL, по умолчанию {@code http://localhost:8080}.
 * </ul>
 *
 * <p><b>Код считается заново перед каждым запросом.</b> При включённой на сервере
 * защите от переигрывания ({@code AUTH_TOTP_REPLAY_PROTECTION}) повторное
 * предъявление того же кода вернёт {@code 401}, хотя сам код ещё не истёк.
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

    /** Значение claim {@code iss}. Должно совпадать при выпуске и проверке. */
    private static final String ISSUER_HOST = "example.com";

    private final String baseUrl;
    private final SecretKeySpec key;
    private final TimeBasedOneTimePasswordGenerator totp;
    private final HttpClient http = HttpClient.newHttpClient();

    /**
     * Создаёт клиент.
     *
     * @param baseUrl базовый URL сервиса
     * @param secret  общий TOTP-секрет в base32
     * @throws Exception если алгоритм HMAC недоступен
     */
    public Java(String baseUrl, String secret) throws Exception {
        this.baseUrl = baseUrl;
        this.key = new SecretKeySpec(new Base32().decode(secret), "HmacSHA1");
        // Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 с.
        this.totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6);
    }

    /**
     * Собирает клиент из переменных окружения.
     *
     * @return готовый клиент
     * @throws Exception если секрет не задан или алгоритм недоступен
     */
    public static Java fromEnv() throws Exception {
        String service = System.getenv().getOrDefault("JWT_SERVICE_URL", "http://localhost:8080");
        String secret = System.getenv("AUTH_TOTP_SECRET");

        if (secret == null) {
            throw new IllegalStateException("нужен AUTH_TOTP_SECRET");
        }

        return new Java(service, secret);
    }

    /**
     * Вычисляет TOTP-код на текущий момент.
     *
     * @return код из шести десятичных знаков
     * @throws Exception при сбое HMAC
     */
    private String totpCode() throws Exception {
        return String.format("%06d", totp.generateOneTimePassword(key, Instant.now()));
    }

    /**
     * Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
     *
     * @param method HTTP-метод
     * @param path   путь ручки, начиная со слеша
     * @param body   тело запроса либо {@code null}, если тела нет
     * @return ответ сервиса
     * @throws Exception при сбое сети или HMAC
     */
    private HttpResponse<String> request(String method, String path, String body) throws Exception {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);

        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                // Код считается здесь, а не переиспользуется: один код — один запрос.
                .header("X-TOTP-Code", totpCode())
                .header("Host", ISSUER_HOST)
                .header("Content-Type", "application/json")
                .method(method, publisher)
                .build();

        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    /**
     * Выпускает access-токен ({@code POST /tokens}).
     *
     * @param sub         субъект, которому выдаётся токен (claim {@code sub})
     * @param aud         получатель (claim {@code aud})
     * @param withRefresh запросить refresh-токен для продления сессии
     * @return тело ответа: {@code {"token": ..., "refresh_token": ...}}
     * @throws Exception {@code 401} — неверный код, {@code 422} — параметры,
     *                   {@code 500} — недоступны JWKS или Redis
     */
    public String issueToken(String sub, String aud, boolean withRefresh) throws Exception {
        String body = """
                {"sub":"%s","aud":["%s"],"refresh":%b}""".formatted(sub, aud, withRefresh);

        HttpResponse<String> response = request("POST", "/tokens", body);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("выпуск не удался: " + response.statusCode());
        }

        return response.body();
    }

    /**
     * Обменивает refresh-токен на новую пару ({@code POST /tokens/refresh}).
     *
     * <p>Старый токен после обмена недействителен: сохраните новый и выбросьте
     * предыдущий.
     *
     * <p><b>Внимание:</b> не повторяйте обмен старым токеном при потере ответа.
     * Повторное предъявление трактуется как кража и гасит всю семью — и
     * refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
     * заново.
     *
     * @param refreshToken токен из выпуска или прошлого обмена
     * @return тело ответа с новой парой
     * @throws Exception {@code 401} — токен неизвестен, истёк или уже использован
     */
    public String refreshTokens(String refreshToken) throws Exception {
        String body = """
                {"refresh_token":"%s"}""".formatted(refreshToken);

        HttpResponse<String> response = request("POST", "/tokens/refresh", body);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("обмен не удался: " + response.statusCode());
        }

        return response.body();
    }

    /**
     * Отзывает один токен по его {@code jti} ({@code DELETE /tokens/{jti}}).
     *
     * <p>Идемпотентно: отзыв несуществующего {@code jti} — тоже успех.
     *
     * @param jti идентификатор токена из claim {@code jti}
     * @throws Exception {@code 500} — хранилище недоступно, отзыв НЕ выполнен
     */
    public void revokeToken(String jti) throws Exception {
        HttpResponse<String> response = request("DELETE", "/tokens/" + jti, null);
        if (response.statusCode() != 204) {
            throw new IllegalStateException("отзыв не удался: " + response.statusCode());
        }
    }

    /**
     * Отзывает все активные токены субъекта.
     *
     * <p>Ручка {@code DELETE /subjects/{sub}/tokens}. Нужна при компрометации:
     * гасить токены по одному нельзя, их {@code jti} вызывающему неизвестны.
     *
     * @param sub субъект, чьи токены гасятся
     * @return тело ответа: {@code {"revoked": N}}; истёкшие токены не считаются
     * @throws Exception {@code 500} — хранилище недоступно, отзыв не выполнен
     */
    public String revokeSubject(String sub) throws Exception {
        HttpResponse<String> response = request("DELETE", "/subjects/" + sub + "/tokens", null);
        if (response.statusCode() != 200) {
            throw new IllegalStateException("массовый отзыв не удался: " + response.statusCode());
        }

        return response.body();
    }

    /**
     * Демонстрирует полный жизненный цикл токена.
     *
     * @param args не используются
     * @throws Exception при любой ошибке сценария
     */
    public static void main(String[] args) throws Exception {
        Java client = Java.fromEnv();

        String issued = client.issueToken("svc-a", "svc-b", true);
        System.out.println("выпущен: " + issued);

        // В боевом коде разберите JSON и достаньте refresh_token библиотекой.
        String refreshToken = issued.replaceAll(".*\"refresh_token\":\"([^\"]+)\".*", "$1");

        System.out.println("обновлён: " + client.refreshTokens(refreshToken));
        System.out.println("массовый отзыв: " + client.revokeSubject("svc-a"));
    }
}
