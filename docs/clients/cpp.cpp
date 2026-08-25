/**
 * @file cpp.cpp
 * @brief jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Build: `c++ -std=c++17 cpp.cpp -lcrypto -o client` (cpp-httplib must be on
 * the include path).
 *
 * Env:
 * - `AUTH_TOTP_SECRET` — shared TOTP secret (see the base32 note below);
 * - `JWT_SERVICE_URL` — base URL, default `http://localhost:8080`.
 *
 * @note This example treats the secret as raw bytes; add a base32 decoder for
 *       Google Authenticator compatibility.
 *
 * @warning The code is recomputed **before every request**. With replay
 *          protection on (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a
 *          code it has already seen with `401`, even while that code is still
 *          inside its time window.
 */

#include <openssl/hmac.h>

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <optional>
#include <string>

#include "httplib.h"

namespace jwt_service {

/// Sent as the Host header and becomes the `iss` claim. Must be the same on
/// issue and on verify, or the token will not verify.
constexpr const char* kIssuerHost = "example.com";

/**
 * @brief Client of the token service, covering all four level 3 endpoints.
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
     * @brief Issues an access token (`POST /tokens`).
     *
     * @param sub          Subject the token is issued to (`sub` claim).
     * @param aud          Audience (`aud` claim).
     * @param with_refresh Also return a refresh token for extending the session.
     * @param claims_json  Custom claims as a JSON object (for example
     *                     `{"role":"admin"}`) or an empty string. They sit next
     *                     to the registered ones; reserved names (`iss`, `sub`,
     *                     `aud`, `exp`, `iat`, `nbf`, `jti`) give `422` —
     *                     change lifetime through `ttl`, not `exp`.
     *
     * @return HTTP status and response body. `401` bad code, `422` bad
     *         parameters or forbidden claim, `500` JWKS or Redis unavailable.
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
     * @brief Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
     *
     * The old token dies on exchange: store the new one and drop the previous.
     *
     * @warning Never retry an exchange with the old token when the reply is
     *          lost. A second presentation reads as theft, and the server
     *          revokes the whole family — refresh tokens and the access tokens
     *          issued from them. Issue a new pair instead.
     *
     * @param refresh_token Token from an issue or a previous exchange.
     *
     * @return HTTP status and response body. `401` — token unknown, expired or
     *         already used.
     */
    std::pair<int, std::string> RefreshTokens(const std::string& refresh_token) {
        const std::string body = "{\"refresh_token\":\"" + refresh_token + "\"}";
        return Request("POST", "/tokens/refresh", body);
    }

    /**
     * @brief Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
     *
     * Idempotent: revoking an unknown `jti` is success too (`204`).
     *
     * @param jti Token id from the `jti` claim.
     *
     * @return HTTP status and response body. `500` — store unreachable and the
     *         token is **not** revoked: retry.
     */
    std::pair<int, std::string> RevokeToken(const std::string& jti) {
        return Request("DELETE", "/tokens/" + jti, std::nullopt);
    }

    /**
     * @brief Revokes every active token of a subject.
     *
     * Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens
     * cannot be killed one by one because the caller does not know their `jti`.
     *
     * @param sub Subject whose tokens are killed.
     *
     * @return HTTP status and a body carrying `revoked`; expired tokens do not
     *         count.
     */
    std::pair<int, std::string> RevokeSubject(const std::string& sub) {
        return Request("DELETE", "/subjects/" + sub + "/tokens", std::nullopt);
    }

private:
    /**
     * @brief Computes a fresh TOTP code for right now.
     *
     * Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
     * RFC 4226 section 5.3.
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
     * @brief Sends a level 3 request.
     *
     * @param method HTTP method.
     * @param path   Endpoint path.
     * @param body   Request body, or `std::nullopt` when there is none.
     *
     * @return HTTP status and response body; status `0` means a network failure.
     */
    std::pair<int, std::string> Request(const std::string& method,
                                        const std::string& path,
                                        std::optional<std::string> body) {
        httplib::Client http(base_url_.c_str());

        // Computed here rather than reused: one code, one request.
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
 * @brief Full token lifecycle: issue, refresh, bulk revoke.
 *
 * @return `0` on success.
 */
int main() {
    auto client = jwt_service::Client::FromEnv();

    auto [issue_status, issued] = client.IssueToken("svc-a", "svc-b", true, R"({"role":"admin"})");
    std::cout << "issue: " << issue_status << " " << issued << "\n";

    // Real code should parse the reply and take refresh_token from it.
    auto [refresh_status, refreshed] = client.RefreshTokens("put-refresh-token-here");
    std::cout << "refresh: " << refresh_status << " " << refreshed << "\n";

    auto [revoke_status, revoked] = client.RevokeSubject("svc-a");
    std::cout << "bulk revoke: " << revoke_status << " " << revoked << "\n";

    return 0;
}
