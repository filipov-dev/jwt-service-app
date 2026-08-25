/**
 * @file cpp.cpp
 * @brief jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Build: `c++ -std=c++17 cpp.cpp -lcrypto -o client` (cpp-httplib must be on
 * the include path).
 *
 * Env: `AUTH_TOTP_SECRET` (raw bytes here, see README.md), `JWT_SERVICE_URL`
 * (default `http://localhost:8080`).
 *
 * See README.md for endpoints, error codes and client rules.
 */

#include <openssl/hmac.h>

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <optional>
#include <string>

#include "httplib.h"

namespace jwt_service {

/// Sent as the Host header, becomes the `iss` claim.
constexpr const char* kIssuerHost = "example.com";

/**
 * @brief Client of the token service.
 */
class Client {
public:
    /**
     * @brief Creates a client.
     *
     * @param base_url Service base URL.
     * @param secret   Shared TOTP secret.
     */
    Client(std::string base_url, std::string secret)
        : base_url_(std::move(base_url)), secret_(std::move(secret)) {}

    /**
     * @brief Builds a client from the environment.
     *
     * @return The client.
     */
    static Client FromEnv() {
        const char* service = std::getenv("JWT_SERVICE_URL");
        const char* secret = std::getenv("AUTH_TOTP_SECRET");

        return Client(service ? service : "http://localhost:8080", secret ? secret : "");
    }

    /**
     * @brief `POST /tokens`
     *
     * @param sub          Subject.
     * @param aud          Audience.
     * @param with_refresh Also ask for a refresh token.
     * @param claims_json  Custom claims as a JSON object, or an empty string.
     *
     * @return HTTP status and response body.
     */
    std::pair<int, std::string> IssueToken(const std::string& sub,
                                           const std::string& aud,
                                           bool with_refresh = false,
                                           const std::string& claims_json = "") {
        std::string body = "{\"sub\":\"" + sub + "\",\"aud\":[\"" + aud +
                           "\"],\"refresh\":" + (with_refresh ? "true" : "false");

        if (!claims_json.empty()) body += ",\"claims\":" + claims_json;
        body += "}";

        return Request("POST", "/tokens", body);
    }

    /**
     * @brief `POST /tokens/refresh` — returns a new pair; the old refresh token
     *        is dead once the call succeeds.
     *
     * @param refresh_token Token from an issue or a previous refresh.
     *
     * @return HTTP status and response body.
     */
    std::pair<int, std::string> RefreshTokens(const std::string& refresh_token) {
        const std::string body = "{\"refresh_token\":\"" + refresh_token + "\"}";
        return Request("POST", "/tokens/refresh", body);
    }

    /**
     * @brief `DELETE /tokens/{jti}` — idempotent.
     *
     * @param jti Token id from the `jti` claim.
     *
     * @return HTTP status and response body.
     */
    std::pair<int, std::string> RevokeToken(const std::string& jti) {
        return Request("DELETE", "/tokens/" + jti, std::nullopt);
    }

    /**
     * @brief `DELETE /subjects/{sub}/tokens`
     *
     * @param sub Subject whose tokens are revoked.
     *
     * @return HTTP status and a body carrying `revoked`.
     */
    std::pair<int, std::string> RevokeSubject(const std::string& sub) {
        return Request("DELETE", "/subjects/" + sub + "/tokens", std::nullopt);
    }

private:
    /**
     * @brief Fresh TOTP code: SHA-1, 6 digits, 30-second step.
     *
     * Truncation follows RFC 4226 section 5.3.
     *
     * @return Six decimal digits.
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
     * @brief Sends a level 3 request with a code computed right before the call.
     *
     * @param method HTTP method.
     * @param path   Endpoint path.
     * @param body   Request body, or `std::nullopt`.
     *
     * @return HTTP status and response body; status `0` means a network failure.
     */
    std::pair<int, std::string> Request(const std::string& method,
                                        const std::string& path,
                                        std::optional<std::string> body) {
        httplib::Client http(base_url_.c_str());

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
 * @brief Issue -> refresh -> revoke.
 *
 * @return `0` on success.
 */
int main() {
    auto client = jwt_service::Client::FromEnv();

    auto [issue_status, issued] = client.IssueToken("svc-a", "svc-b", true, R"({"role":"admin"})");
    std::cout << "issue: " << issue_status << " " << issued << "\n";

    // Real code should parse the response and take refresh_token from it.
    auto [refresh_status, refreshed] = client.RefreshTokens("put-refresh-token-here");
    std::cout << "refresh: " << refresh_status << " " << refreshed << "\n";

    auto [revoke_status, revoked] = client.RevokeSubject("svc-a");
    std::cout << "bulk revoke: " << revoke_status << " " << revoked << "\n";

    return 0;
}
