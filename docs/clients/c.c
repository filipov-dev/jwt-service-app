/**
 * @file c.c
 * @brief Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
 * токена и массовый отзыв токенов субъекта.
 *
 * Сборка: `cc c.c -lcrypto -lcurl -o client`
 *
 * Окружение:
 * - `AUTH_TOTP_SECRET` — общий TOTP-секрет (см. примечание о base32);
 * - `JWT_SERVICE_URL` — базовый URL, по умолчанию `http://localhost:8080`.
 *
 * @note Пример трактует секрет как сырые байты; для совместимости с Google
 *       Authenticator добавьте декодер base32.
 *
 * @warning Код считается **заново перед каждым запросом**. При включённой на
 *          сервере защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`)
 *          повторное предъявление того же кода вернёт `401`, хотя сам код ещё не
 *          истёк.
 */

#include <curl/curl.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** Значение claim `iss`. Должно совпадать при выпуске и проверке токена. */
#define ISSUER_HOST "example.com"

/**
 * @brief Вычисляет TOTP-код на текущий момент.
 *
 * Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
 * Усечение — по RFC 4226 §5.3.
 *
 * @param[out] out Буфер не менее 7 байт, куда пишется код с завершающим нулём.
 */
static void totp_code(char *out) {
    const char *secret = getenv("AUTH_TOTP_SECRET");
    unsigned long counter = (unsigned long) (time(NULL) / 30);

    unsigned char message[8];
    for (int i = 7; i >= 0; --i) {
        message[i] = (unsigned char) (counter & 0xff);
        counter >>= 8;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    HMAC(EVP_sha1(), secret, (int) strlen(secret), message, sizeof(message), digest, &length);

    int offset = digest[length - 1] & 0x0f;
    unsigned int code = ((digest[offset] & 0x7f) << 24)
                      | (digest[offset + 1] << 16)
                      | (digest[offset + 2] << 8)
                      | digest[offset + 3];

    snprintf(out, 7, "%06u", code % 1000000);
}

/**
 * @brief Возвращает базовый URL сервиса из окружения.
 *
 * @return URL сервиса либо значение по умолчанию.
 */
static const char *service_url(void) {
    const char *service = getenv("JWT_SERVICE_URL");
    return service ? service : "http://localhost:8080";
}

/**
 * @brief Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
 *
 * @param method HTTP-метод (`POST`, `DELETE`).
 * @param path   Путь ручки, начиная со слеша.
 * @param body   Тело запроса либо `NULL`, если тела нет.
 *
 * @return HTTP-код ответа либо `0` при сбое сети.
 */
static long request(const char *method, const char *path, const char *body) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[512];
    snprintf(url, sizeof(url), "%s%s", service_url(), path);

    /* Код считается здесь, а не переиспользуется: один код — один запрос. */
    char code[7];
    totp_code(code);

    char code_header[32];
    snprintf(code_header, sizeof(code_header), "X-TOTP-Code: %s", code);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, code_header);
    headers = curl_slist_append(headers, "Host: " ISSUER_HOST);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

    long status = 0;
    if (curl_easy_perform(curl) == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return status;
}

/**
 * @brief Выпускает access-токен (`POST /tokens`).
 *
 * @param sub          Субъект, которому выдаётся токен (claim `sub`).
 * @param aud          Получатель (claim `aud`).
 * @param with_refresh Запросить refresh-токен для продления сессии.
 *
 * @return HTTP-код: `200` — успех, `401` — неверный код, `422` — параметры,
 *         `500` — недоступны JWKS или Redis.
 */
long issue_token(const char *sub, const char *aud, int with_refresh) {
    char body[256];
    snprintf(body, sizeof(body), "{\"sub\":\"%s\",\"aud\":[\"%s\"],\"refresh\":%s}",
             sub, aud, with_refresh ? "true" : "false");

    return request("POST", "/tokens", body);
}

/**
 * @brief Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
 *
 * Старый токен после обмена недействителен: сохраните новый и выбросьте
 * предыдущий.
 *
 * @warning Не повторяйте обмен старым токеном при потере ответа. Повторное
 *          предъявление трактуется как кража и гасит всю семью — и refresh-токены,
 *          и выданные по ним access-токены. Надёжнее выпустить пару заново.
 *
 * @param refresh_token Токен из выпуска или прошлого обмена.
 *
 * @return HTTP-код: `200` — успех, `401` — токен неизвестен, истёк или уже
 *         использован.
 */
long refresh_tokens(const char *refresh_token) {
    char body[512];
    snprintf(body, sizeof(body), "{\"refresh_token\":\"%s\"}", refresh_token);

    return request("POST", "/tokens/refresh", body);
}

/**
 * @brief Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
 *
 * Идемпотентно: отзыв несуществующего `jti` — тоже успех (`204`).
 *
 * @param jti Идентификатор токена из claim `jti`.
 *
 * @return HTTP-код: `204` — успех, `500` — хранилище недоступно и отзыв **не
 *         выполнен**, попытку следует повторить.
 */
long revoke_token(const char *jti) {
    char path[256];
    snprintf(path, sizeof(path), "/tokens/%s", jti);

    return request("DELETE", path, NULL);
}

/**
 * @brief Отзывает все активные токены субъекта.
 *
 * Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить токены
 * по одному нельзя, их `jti` вызывающему неизвестны.
 *
 * @param sub Субъект, чьи токены гасятся.
 *
 * @return HTTP-код: `200` — успех; в теле ответа поле `revoked` с числом
 *         отозванных токенов (истёкшие не считаются).
 */
long revoke_subject(const char *sub) {
    char path[256];
    snprintf(path, sizeof(path), "/subjects/%s/tokens", sub);

    return request("DELETE", path, NULL);
}

/**
 * @brief Демонстрирует полный жизненный цикл токена.
 *
 * @return `0` при успехе.
 */
int main(void) {
    printf("выпуск: %ld\n", issue_token("svc-a", "svc-b", 1));

    /* В боевом коде разберите JSON ответа и достаньте refresh_token. */
    printf("обмен: %ld\n", refresh_tokens("положите-сюда-refresh_token"));
    printf("массовый отзыв: %ld\n", revoke_subject("svc-a"));

    return 0;
}
