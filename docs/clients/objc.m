/**
 * @file objc.m
 * @brief Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
 * токена и массовый отзыв токенов субъекта.
 *
 * Сборка: `clang -fobjc-arc objc.m -framework Foundation -o client`
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

#import <CommonCrypto/CommonHMAC.h>
#import <Foundation/Foundation.h>

/** Значение claim `iss`. Должно совпадать при выпуске и проверке токена. */
static NSString *const kIssuerHost = @"example.com";

/**
 * @brief Клиент сервиса выдачи токенов.
 */
@interface JwtServiceClient : NSObject

/**
 * @brief Создаёт клиент из переменных окружения.
 *
 * @return Готовый клиент.
 */
+ (instancetype)clientFromEnvironment;

/**
 * @brief Выпускает access-токен (`POST /tokens`).
 *
 * @param subject     Субъект, которому выдаётся токен (claim `sub`).
 * @param audience    Получатель (claim `aud`).
 * @param withRefresh Запросить refresh-токен для продления сессии.
 *
 * @return Тело ответа; `nil` при ошибке. Коды: `401` — неверный код,
 *         `422` — параметры, `500` — недоступны JWKS или Redis.
 */
- (nullable NSString *)issueTokenForSubject:(NSString *)subject
                                   audience:(NSString *)audience
                                withRefresh:(BOOL)withRefresh;

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
 * @param refreshToken Токен из выпуска или прошлого обмена.
 *
 * @return Тело ответа с новой парой; `nil`, если токен неизвестен, истёк или уже
 *         использован (`401`).
 */
- (nullable NSString *)refreshTokens:(NSString *)refreshToken;

/**
 * @brief Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
 *
 * Идемпотентно: отзыв несуществующего `jti` — тоже успех (`204`).
 *
 * @param jti Идентификатор токена из claim `jti`.
 *
 * @return `YES` при успехе; `NO` означает `500` — хранилище недоступно и отзыв
 *         **не выполнен**, попытку следует повторить.
 */
- (BOOL)revokeToken:(NSString *)jti;

/**
 * @brief Отзывает все активные токены субъекта.
 *
 * Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить токены
 * по одному нельзя, их `jti` вызывающему неизвестны.
 *
 * @param subject Субъект, чьи токены гасятся.
 *
 * @return Тело ответа с полем `revoked`; истёкшие токены не считаются.
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
 * @brief Вычисляет TOTP-код на текущий момент.
 *
 * Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
 * Усечение — по RFC 4226 §5.3.
 *
 * @return Код из шести десятичных знаков.
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
 * @brief Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
 *
 * @param method HTTP-метод.
 * @param path   Путь ручки, начиная со слеша.
 * @param body   Тело запроса либо `nil`, если тела нет.
 * @param status Сюда пишется HTTP-код ответа.
 *
 * @return Тело ответа либо `nil` при сбое сети.
 */
- (nullable NSString *)request:(NSString *)method
                          path:(NSString *)path
                          body:(nullable NSString *)body
                        status:(NSInteger *)status {
    NSURL *url = [NSURL URLWithString:[_baseURL stringByAppendingString:path]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = method;

    // Код считается здесь, а не переиспользуется: один код — один запрос.
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
                                withRefresh:(BOOL)withRefresh {
    NSString *body = [NSString
        stringWithFormat:@"{\"sub\":\"%@\",\"aud\":[\"%@\"],\"refresh\":%@}", subject, audience,
                         withRefresh ? @"true" : @"false"];

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
 * @brief Демонстрирует полный жизненный цикл токена.
 *
 * @return `0` при успехе.
 */
int main(void) {
    @autoreleasepool {
        JwtServiceClient *client = [JwtServiceClient clientFromEnvironment];

        NSLog(@"выпущен: %@", [client issueTokenForSubject:@"svc-a"
                                                 audience:@"svc-b"
                                              withRefresh:YES]);

        // В боевом коде разберите JSON через NSJSONSerialization.
        NSLog(@"обновлён: %@", [client refreshTokens:@"положите-сюда-refresh_token"]);
        NSLog(@"массовый отзыв: %@", [client revokeSubject:@"svc-a"]);
    }

    return 0;
}
