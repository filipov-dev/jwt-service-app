/**
 * @file cpp.cpp
 * @brief Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
 * токена и массовый отзыв токенов субъекта.
 *
 * Сборка: `c++ -std=c++17 cpp.cpp -lcrypto -o client` (нужен cpp-httplib в
 * include-путях).
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

#include <openssl/hmac.h>

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <optional>
#include <string>

#include "httplib.h"

namespace jwt_service {

/// Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
constexpr const char* kIssuerHost = "example.com";

/**
 * @brief Клиент сервиса выдачи токенов.
 */
class Client {
public:
    /**
     * @brief Создаёт клиент.
     *
     * @param base_url Базовый URL сервиса.
     * @param secret   Общий TOTP-секрет.
     */
    Client(std::string base_url, std::string secret)
        : base_url_(std::move(base_url)), secret_(std::move(secret)) {}

    /**
     * @brief Собирает клиент из переменных окружения.
     *
     * @return Готовый клиент.
     */
    static Client FromEnv() {
        const char* service = std::getenv("JWT_SERVICE_URL");
        const char* secret = std::getenv("AUTH_TOTP_SECRET");

        return Client(service ? service : "http://localhost:8080", secret ? secret : "");
    }

    /**
     * @brief Выпускает access-токен (`POST /tokens`).
     *
     * @param sub          Субъект, которому выдаётся токен (claim `sub`).
     * @param aud          Получатель (claim `aud`).
     * @param with_refresh Запросить refresh-токен для продления сессии.
     *
     * @return HTTP-код и тело ответа. `401` — неверный код, `422` — параметры,
     *         `500` — недоступны JWKS или Redis.
     */
    std::pair<int, std::string> IssueToken(const std::string& sub,
                                           const std::string& aud,
                                           bool with_refresh = false) {
        const std::string body = "{\"sub\":\"" + sub + "\",\"aud\":[\"" + aud +
                                 "\"],\"refresh\":" + (with_refresh ? "true" : "false") + "}";

        return Request("POST", "/tokens", body);
    }

    /**
     * @brief Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
     *
     * Старый токен после обмена недействителен: сохраните новый и выбросьте
     * предыдущий.
     *
     * @warning Не повторяйте обмен старым токеном при потере ответа. Повторное
     *          предъявление трактуется как кража и гасит всю семью — и
     *          refresh-токены, и выданные по ним access-токены. Надёжнее
     *          выпустить пару заново.
     *
     * @param refresh_token Токен из выпуска или прошлого обмена.
     *
     * @return HTTP-код и тело ответа. `401` — токен неизвестен, истёк или уже
     *         использован.
     */
    std::pair<int, std::string> RefreshTokens(const std::string& refresh_token) {
        const std::string body = "{\"refresh_token\":\"" + refresh_token + "\"}";
        return Request("POST", "/tokens/refresh", body);
    }

    /**
     * @brief Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
     *
     * Идемпотентно: отзыв несуществующего `jti` — тоже успех (`204`).
     *
     * @param jti Идентификатор токена из claim `jti`.
     *
     * @return HTTP-код и тело ответа. `500` — хранилище недоступно и отзыв **не
     *         выполнен**: попытку следует повторить.
     */
    std::pair<int, std::string> RevokeToken(const std::string& jti) {
        return Request("DELETE", "/tokens/" + jti, std::nullopt);
    }

    /**
     * @brief Отзывает все активные токены субъекта.
     *
     * Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить
     * токены по одному нельзя, их `jti` вызывающему неизвестны.
     *
     * @param sub Субъект, чьи токены гасятся.
     *
     * @return HTTP-код и тело с полем `revoked`; истёкшие токены не считаются.
     */
    std::pair<int, std::string> RevokeSubject(const std::string& sub) {
        return Request("DELETE", "/subjects/" + sub + "/tokens", std::nullopt);
    }

private:
    /**
     * @brief Вычисляет TOTP-код на текущий момент.
     *
     * Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
     * Усечение — по RFC 4226 §5.3.
     *
     * @return Код из шести десятичных знаков.
     */
    std::string TotpCode() const {
        auto counter = static_cast<unsigned long>(std::time(nullptr) / 30);

        unsigned char message[8];
        for (int i = 7; i >= 0; --i) {
            message[i] = static_cast<unsigned char>(counter & 0xff);
            counter >>= 8;
        }

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        HMAC(EVP_sha1(), secret_.data(), static_cast<int>(secret_.size()), message,
             sizeof(message), digest, &length);

        const int offset = digest[length - 1] & 0x0f;
        const unsigned int code = ((digest[offset] & 0x7f) << 24) |
                                  (digest[offset + 1] << 16) |
                                  (digest[offset + 2] << 8) |
                                  digest[offset + 3];

        char buffer[7];
        std::snprintf(buffer, sizeof(buffer), "%06u", code % 1000000);
        return buffer;
    }

    /**
     * @brief Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
     *
     * @param method HTTP-метод.
     * @param path   Путь ручки, начиная со слеша.
     * @param body   Тело запроса либо `std::nullopt`, если тела нет.
     *
     * @return HTTP-код и тело ответа; код `0` означает сбой сети.
     */
    std::pair<int, std::string> Request(const std::string& method,
                                        const std::string& path,
                                        std::optional<std::string> body) {
        httplib::Client http(base_url_.c_str());

        // Код считается здесь, а не переиспользуется: один код — один запрос.
        const httplib::Headers headers = {
            {"X-TOTP-Code", TotpCode()},
            {"Host", kIssuerHost},
        };

        httplib::Result result =
            body ? http.Post(path.c_str(), headers, *body, "application/json")
                 : http.Delete(path.c_str(), headers);

        if (!result) return {0, {}};
        return {result->status, result->body};
    }

    std::string base_url_;
    std::string secret_;
};

}  // namespace jwt_service

/**
 * @brief Демонстрирует полный жизненный цикл токена.
 *
 * @return `0` при успехе.
 */
int main() {
    auto client = jwt_service::Client::FromEnv();

    auto [issue_status, issued] = client.IssueToken("svc-a", "svc-b", true);
    std::cout << "выпуск: " << issue_status << " " << issued << "\n";

    // В боевом коде разберите JSON ответа и достаньте refresh_token.
    auto [refresh_status, refreshed] = client.RefreshTokens("положите-сюда-refresh_token");
    std::cout << "обмен: " << refresh_status << " " << refreshed << "\n";

    auto [revoke_status, revoked] = client.RevokeSubject("svc-a");
    std::cout << "массовый отзыв: " << revoke_status << " " << revoked << "\n";

    return 0;
}
