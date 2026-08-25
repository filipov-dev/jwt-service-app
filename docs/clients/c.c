/**
 * @file c.c
 * @brief jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Build: `cc c.c -lcrypto -lcurl -o client`
 *
 * Env: `AUTH_TOTP_SECRET` (raw bytes here, see README.md), `JWT_SERVICE_URL`
 * (default `http://localhost:8080`).
 *
 * See README.md for endpoints, error codes and client rules.
 */

#include <curl/curl.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/** Sent as the Host header, becomes the `iss` claim. */
#define ISSUER_HOST "example.com"

/**
 * @brief Fresh TOTP code: SHA-1, 6 digits, 30-second step.
 *
 * Truncation follows RFC 4226 section 5.3.
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
 * @brief Service base URL from the environment.
 *
 * @return The URL, or the default.
 */
static const char *service_url(void) {
    const char *service = getenv("JWT_SERVICE_URL");
    return service ? service : "http://localhost:8080";
}

/**
 * @brief Sends a level 3 request with a code computed right before the call.
 *
 * @param method HTTP method.
 * @param path   Endpoint path.
 * @param body   Request body, or `NULL`.
 *
 * @return HTTP status, or `0` on a network failure.
 */
static long request(const char *method, const char *path, const char *body) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[512];
    snprintf(url, sizeof(url), "%s%s", service_url(), path);

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
 * @brief `POST /tokens`
 *
 * @param sub          Subject.
 * @param aud          Audience.
 * @param with_refresh Also ask for a refresh token.
 * @param claims_json  Custom claims as a JSON object, or `NULL`.
 *
 * @return HTTP status.
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
 * @brief `POST /tokens/refresh` — returns a new pair; the old refresh token is
 *        dead once the call succeeds.
 *
 * @param refresh_token Token from an issue or a previous refresh.
 *
 * @return HTTP status.
 */
long refresh_tokens(const char *refresh_token) {
    char body[512];
    snprintf(body, sizeof(body), "{\"refresh_token\":\"%s\"}", refresh_token);

    return request("POST", "/tokens/refresh", body);
}

/**
 * @brief `DELETE /tokens/{jti}` — idempotent.
 *
 * @param jti Token id from the `jti` claim.
 *
 * @return HTTP status.
 */
long revoke_token(const char *jti) {
    char path[256];
    snprintf(path, sizeof(path), "/tokens/%s", jti);

    return request("DELETE", path, NULL);
}

/**
 * @brief `DELETE /subjects/{sub}/tokens`
 *
 * @param sub Subject whose tokens are revoked.
 *
 * @return HTTP status; the body carries `revoked` with the count.
 */
long revoke_subject(const char *sub) {
    char path[256];
    snprintf(path, sizeof(path), "/subjects/%s/tokens", sub);

    return request("DELETE", path, NULL);
}

/**
 * @brief Issue -> refresh -> revoke.
 *
 * @return `0` on success.
 */
int main(void) {
    printf("issue: %ld\n", issue_token("svc-a", "svc-b", 1, "{\"role\":\"admin\"}"));

    /* Real code should parse the response and take refresh_token from it. */
    printf("refresh: %ld\n", refresh_tokens("put-refresh-token-here"));
    printf("bulk revoke: %ld\n", revoke_subject("svc-a"));

    return 0;
}
