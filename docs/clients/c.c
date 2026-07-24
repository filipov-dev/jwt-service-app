/* C — TOTP через OpenSSL HMAC + libcurl.
 * Сборка: cc totp.c -lcrypto -lcurl -o totp
 * Секрет AUTH_TOTP_SECRET здесь ожидается как СЫРЫЕ байты (для base32 добавьте
 * декодер, напр. из liboath). SHA-1, 6 знаков, шаг 30с. */
#include <openssl/hmac.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(void) {
    const char *secret = getenv("AUTH_TOTP_SECRET");
    const char *service = getenv("JWT_SERVICE_URL");
    if (!service) service = "http://localhost:8080";

    unsigned long long counter = (unsigned long long)(time(NULL) / 30);
    unsigned char msg[8];
    for (int i = 7; i >= 0; --i) { msg[i] = counter & 0xff; counter >>= 8; }

    unsigned char hs[EVP_MAX_MD_SIZE]; unsigned int len = 0;
    HMAC(EVP_sha1(), secret, (int)strlen(secret), msg, 8, hs, &len);

    int off = hs[len - 1] & 0x0f;
    unsigned int bin = ((hs[off] & 0x7f) << 24) | (hs[off+1] << 16) | (hs[off+2] << 8) | hs[off+3];
    char code[7];
    snprintf(code, sizeof code, "%06u", bin % 1000000u);

    char header[64];
    snprintf(header, sizeof header, "X-TOTP-Code: %s", code);

    CURL *c = curl_easy_init();
    struct curl_slist *h = NULL;
    h = curl_slist_append(h, header);
    h = curl_slist_append(h, "Host: example.com");
    h = curl_slist_append(h, "Content-Type: application/json");
    char url[256]; snprintf(url, sizeof url, "%s/tokens", service);
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, "{\"sub\":\"svc-a\",\"aud\":[\"svc-b\"]}");
    curl_easy_perform(c);
    curl_easy_cleanup(c);
    return 0;
}
