/**
 * @file c.c
 * @brief jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Build: `cc c.c -lcrypto -lcurl -o client`
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

#include <curl/curl.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * Sent as the Host header and becomes the `iss` claim. Must be the same on
 * issue and on verify, or the token will not verify.
 */
#define ISSUER_HOST "example.com"

/**
 * @brief Computes a fresh TOTP code for right now.
 *
 * Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
 * RFC 4226 section 5.3.
 *
 * @param[out] out Buffer of at least 7 bytes for the NUL-terminated code.
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
 * @brief Returns the service base URL from the environment.
 *
 * @return The URL, or the default.
 */
static const char *service_url(void) {
    const char *service = getenv("JWT_SERVICE_URL");
    return service ? service : "http://localhost:8080";
}

/**
 * @brief Sends a level 3 request.
 *
 * @param method HTTP method (`POST`, `DELETE`).
 * @param path   Endpoint path.
 * @param body   Request body, or `NULL` when there is none.
 *
 * @return HTTP status, or `0` on a network failure.
 */
static long request(const char *method, const char *path, const char *body) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[512];
    snprintf(url, sizeof(url), "%s%s", service_url(), path);

    /* Computed here rather than reused: one code, one request. */
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
 * @brief Issues an access token (`POST /tokens`).
 *
 * @param sub          Subject the token is issued to (`sub` claim).
 * @param aud          Audience (`aud` claim).
 * @param with_refresh Also return a refresh token for extending the session.
 * @param claims_json  Custom claims as a JSON object (for example
 *                     `{"role":"admin"}`) or `NULL`. They sit next to the
 *                     registered ones; reserved names (`iss`, `sub`, `aud`,
 *                     `exp`, `iat`, `nbf`, `jti`) give `422` — change lifetime
 *                     through `ttl`, not `exp`.
 *
 * @return HTTP status: `200` success, `401` bad code, `422` bad parameters or
 *         forbidden claim, `500` JWKS or Redis unavailable.
 */
long issue_token(const char *sub, const char *aud, int with_refresh, const char *claims_json) {
    char body[1024];

    if (claims_json) {
        snprintf(body, sizeof(body),
                 "{\"sub\":\"%s\",\"aud\":[\"%s\"],\"refresh\":%s,\"claims\":%s}",
                 sub, aud, with_refresh ? "true" : "false", claims_json);
    } else {
        snprintf(body, sizeof(body), "{\"sub\":\"%s\",\"aud\":[\"%s\"],\"refresh\":%s}",
                 sub, aud, with_refresh ? "true" : "false");
    }

    return request("POST", "/tokens", body);
}

/**
 * @brief Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
 *
 * The old token dies on exchange: store the new one and drop the previous.
 *
 * @warning Never retry an exchange with the old token when the reply is lost. A
 *          second presentation reads as theft, and the server revokes the whole
 *          family — refresh tokens and the access tokens issued from them.
 *          Issue a new pair instead.
 *
 * @param refresh_token Token from an issue or a previous exchange.
 *
 * @return HTTP status: `200` success, `401` token unknown, expired or already
 *         used.
 */
long refresh_tokens(const char *refresh_token) {
    char body[512];
    snprintf(body, sizeof(body), "{\"refresh_token\":\"%s\"}", refresh_token);

    return request("POST", "/tokens/refresh", body);
}

/**
 * @brief Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
 *
 * Idempotent: revoking an unknown `jti` is success too (`204`).
 *
 * @param jti Token id from the `jti` claim.
 *
 * @return HTTP status: `204` success, `500` store unreachable and the token is
 *         **not** revoked — retry.
 */
long revoke_token(const char *jti) {
    char path[256];
    snprintf(path, sizeof(path), "/tokens/%s", jti);

    return request("DELETE", path, NULL);
}

/**
 * @brief Revokes every active token of a subject.
 *
 * Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens cannot
 * be killed one by one because the caller does not know their `jti`.
 *
 * @param sub Subject whose tokens are killed.
 *
 * @return HTTP status: `200` success; the body carries `revoked` with the count
 *         (expired tokens do not count).
 */
long revoke_subject(const char *sub) {
    char path[256];
    snprintf(path, sizeof(path), "/subjects/%s/tokens", sub);

    return request("DELETE", path, NULL);
}

/**
 * @brief Full token lifecycle: issue, refresh, bulk revoke.
 *
 * @return `0` on success.
 */
int main(void) {
    printf("issue: %ld\n", issue_token("svc-a", "svc-b", 1, "{\"role\":\"admin\"}"));

    /* Real code should parse the reply and take refresh_token from it. */
    printf("refresh: %ld\n", refresh_tokens("put-refresh-token-here"));
    printf("bulk revoke: %ld\n", revoke_subject("svc-a"));

    return 0;
}
