/**
 * @file objc.m
 * @brief jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Build: `clang -fobjc-arc objc.m -framework Foundation -o client`
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

#import <CommonCrypto/CommonHMAC.h>
#import <Foundation/Foundation.h>

/**
 * Sent as the Host header and becomes the `iss` claim. Must be the same on
 * issue and on verify, or the token will not verify.
 */
static NSString *const kIssuerHost = @"example.com";

/**
 * @brief Client of the token service, covering all four level 3 endpoints.
 */
@interface JwtServiceClient : NSObject

/**
 * @brief Builds a client from the environment.
 *
 * @return The client.
 */
+ (instancetype)clientFromEnvironment;

/**
 * @brief Issues an access token (`POST /tokens`).
 *
 * @param subject     Subject the token is issued to (`sub` claim).
 * @param audience    Audience (`aud` claim).
 * @param withRefresh Also return a refresh token for extending the session.
 * @param claimsJson  Custom claims as a JSON object (for example
 *        `@"{\"role\":\"admin\"}"`) or `nil`. They sit next to the registered
 *        ones; reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`)
 *        give `422` — change lifetime through `ttl`, not `exp`.
 *
 * @return Response body, or `nil` on failure. `401` bad code, `422` bad
 *         parameters or forbidden claim, `500` JWKS or Redis unavailable.
 */
- (nullable NSString *)issueTokenForSubject:(NSString *)subject
                                   audience:(NSString *)audience
                                withRefresh:(BOOL)withRefresh
                                 claimsJson:(nullable NSString *)claimsJson;

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
 * @param refreshToken Token from an issue or a previous exchange.
 *
 * @return Response body with the new pair; `nil` if the token is unknown,
 *         expired or already used (`401`).
 */
- (nullable NSString *)refreshTokens:(NSString *)refreshToken;

/**
 * @brief Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
 *
 * Idempotent: revoking an unknown `jti` is success too (`204`).
 *
 * @param jti Token id from the `jti` claim.
 *
 * @return `YES` on success; `NO` means `500` — the store is unreachable and the
 *         token is **not** revoked, retry.
 */
- (BOOL)revokeToken:(NSString *)jti;

/**
 * @brief Revokes every active token of a subject.
 *
 * Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens cannot
 * be killed one by one because the caller does not know their `jti`.
 *
 * @param subject Subject whose tokens are killed.
 *
 * @return Response body carrying `revoked`; expired tokens do not count.
 */
- (nullable NSString *)revokeSubject:(NSString *)subject;

@end

@implementation JwtServiceClient {
    NSString *_baseURL;
    NSData *_secret;
}

+ (instancetype)clientFromEnvironment {
    NSDictionary *env = NSProcessInfo.processInfo.environment;

    JwtServiceClient *client = [[JwtServiceClient alloc] init];
    client->_baseURL = env[@"JWT_SERVICE_URL"] ?: @"http://localhost:8080";
    client->_secret = [env[@"AUTH_TOTP_SECRET"] dataUsingEncoding:NSUTF8StringEncoding];

    return client;
}

/**
 * @brief Computes a fresh TOTP code for right now.
 *
 * Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
 * RFC 4226 section 5.3.
 *
 * @return Six decimal digits.
 */
- (NSString *)totpCode {
    uint64_t counter = (uint64_t)(NSDate.date.timeIntervalSince1970 / 30);

    uint8_t message[8];
    for (int i = 7; i >= 0; --i) {
        message[i] = counter & 0xff;
        counter >>= 8;
    }

    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA1, _secret.bytes, _secret.length, message, sizeof(message), digest);

    int offset = digest[CC_SHA1_DIGEST_LENGTH - 1] & 0x0f;
    uint32_t code = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) |
                    (digest[offset + 2] << 8) | digest[offset + 3];

    return [NSString stringWithFormat:@"%06u", code % 1000000];
}

/**
 * @brief Sends a level 3 request.
 *
 * @param method HTTP method.
 * @param path   Endpoint path.
 * @param body   Request body, or `nil` when there is none.
 * @param status Receives the HTTP status.
 *
 * @return Response body, or `nil` on a network failure.
 */
- (nullable NSString *)request:(NSString *)method
                          path:(NSString *)path
                          body:(nullable NSString *)body
                        status:(NSInteger *)status {
    NSURL *url = [NSURL URLWithString:[_baseURL stringByAppendingString:path]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = method;

    // Computed here rather than reused: one code, one request.
    [request setValue:[self totpCode] forHTTPHeaderField:@"X-TOTP-Code"];
    [request setValue:kIssuerHost forHTTPHeaderField:@"Host"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    if (body) {
        request.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];
    }

    __block NSString *result = nil;
    __block NSInteger code = 0;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);

    [[NSURLSession.sharedSession
        dataTaskWithRequest:request
          completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
              code = ((NSHTTPURLResponse *)response).statusCode;
              if (data) {
                  result = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
              }
              dispatch_semaphore_signal(done);
          }] resume];

    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    *status = code;

    return result;
}

- (nullable NSString *)issueTokenForSubject:(NSString *)subject
                                   audience:(NSString *)audience
                                withRefresh:(BOOL)withRefresh
                                 claimsJson:(nullable NSString *)claimsJson {
    NSString *claimsPart =
        claimsJson ? [NSString stringWithFormat:@",\"claims\":%@", claimsJson] : @"";

    NSString *body = [NSString
        stringWithFormat:@"{\"sub\":\"%@\",\"aud\":[\"%@\"],\"refresh\":%@%@}", subject,
                         audience, withRefresh ? @"true" : @"false", claimsPart];

    NSInteger status = 0;
    NSString *response = [self request:@"POST" path:@"/tokens" body:body status:&status];

    return status == 200 ? response : nil;
}

- (nullable NSString *)refreshTokens:(NSString *)refreshToken {
    NSString *body =
        [NSString stringWithFormat:@"{\"refresh_token\":\"%@\"}", refreshToken];

    NSInteger status = 0;
    NSString *response = [self request:@"POST" path:@"/tokens/refresh" body:body status:&status];

    return status == 200 ? response : nil;
}

- (BOOL)revokeToken:(NSString *)jti {
    NSInteger status = 0;
    [self request:@"DELETE"
             path:[@"/tokens/" stringByAppendingString:jti]
             body:nil
           status:&status];

    return status == 204;
}

- (nullable NSString *)revokeSubject:(NSString *)subject {
    NSString *path = [NSString stringWithFormat:@"/subjects/%@/tokens", subject];

    NSInteger status = 0;
    NSString *response = [self request:@"DELETE" path:path body:nil status:&status];

    return status == 200 ? response : nil;
}

@end

/**
 * @brief Full token lifecycle: issue, refresh, bulk revoke.
 *
 * @return `0` on success.
 */
int main(void) {
    @autoreleasepool {
        JwtServiceClient *client = [JwtServiceClient clientFromEnvironment];

        NSLog(@"issued: %@", [client issueTokenForSubject:@"svc-a"
                                                 audience:@"svc-b"
                                              withRefresh:YES
                                               claimsJson:@"{\"role\":\"admin\"}"]);

        // Real code should parse the JSON with NSJSONSerialization.
        NSLog(@"refreshed: %@", [client refreshTokens:@"put-refresh-token-here"]);
        NSLog(@"bulk revoke: %@", [client revokeSubject:@"svc-a"]);
    }

    return 0;
}
