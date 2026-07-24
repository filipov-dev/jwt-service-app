// C++ — библиотека: cpp-httplib (header-only) + OpenSSL HMAC.
// Сборка: c++ -std=c++17 totp.cpp -lcrypto -lssl -o totp
// AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (для base32 добавьте декодер).
#include <openssl/hmac.h>
#include <httplib.h>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <string>

int main() {
    std::string secret = std::getenv("AUTH_TOTP_SECRET");
    const char* svc = std::getenv("JWT_SERVICE_URL");
    std::string service = svc ? svc : "http://localhost:8080";

    unsigned long long counter = std::time(nullptr) / 30;
    unsigned char msg[8];
    for (int i = 7; i >= 0; --i) { msg[i] = counter & 0xff; counter >>= 8; }

    unsigned char hs[EVP_MAX_MD_SIZE]; unsigned int len = 0;
    HMAC(EVP_sha1(), secret.data(), (int)secret.size(), msg, 8, hs, &len);
    int off = hs[len - 1] & 0x0f;
    unsigned int bin = ((hs[off] & 0x7f) << 24) | (hs[off+1] << 16) | (hs[off+2] << 8) | hs[off+3];
    char code[7]; std::snprintf(code, sizeof code, "%06u", bin % 1000000u);

    httplib::Client cli(service.c_str());
    httplib::Headers headers = {{"X-TOTP-Code", code}, {"Host", "example.com"}};
    auto res = cli.Post("/tokens", headers, R"({"sub":"svc-a","aud":["svc-b"]})", "application/json");
    if (res) std::printf("%d\n", res->status);
    return 0;
}
