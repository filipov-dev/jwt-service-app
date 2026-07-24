// Objective-C — TOTP через CommonCrypto HMAC + NSURLSession.
// AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (для base32 добавьте декодер).
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonHMAC.h>

int main() {
    @autoreleasepool {
        NSDictionary *env = NSProcessInfo.processInfo.environment;
        NSData *key = [env[@"AUTH_TOTP_SECRET"] dataUsingEncoding:NSUTF8StringEncoding];
        NSString *service = env[@"JWT_SERVICE_URL"] ?: @"http://localhost:8080";

        uint64_t counter = CFAbsoluteTimeGetCurrent() + kCFAbsoluteTimeIntervalSince1970;
        counter = (uint64_t)(time(NULL) / 30);
        uint8_t msg[8];
        for (int i = 7; i >= 0; --i) { msg[i] = counter & 0xff; counter >>= 8; }

        uint8_t hs[CC_SHA1_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA1, key.bytes, key.length, msg, 8, hs);
        int off = hs[CC_SHA1_DIGEST_LENGTH - 1] & 0x0f;
        uint32_t bin = ((hs[off] & 0x7f) << 24) | (hs[off+1] << 16) | (hs[off+2] << 8) | hs[off+3];
        NSString *code = [NSString stringWithFormat:@"%06u", bin % 1000000u];

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:
            [NSURL URLWithString:[service stringByAppendingString:@"/tokens"]]];
        req.HTTPMethod = @"POST";
        [req setValue:code forHTTPHeaderField:@"X-TOTP-Code"];
        [req setValue:@"example.com" forHTTPHeaderField:@"Host"];
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = [@"{\"sub\":\"svc-a\",\"aud\":[\"svc-b\"]}" dataUsingEncoding:NSUTF8StringEncoding];

        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [[NSURLSession.sharedSession dataTaskWithRequest:req
            completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                NSLog(@"%ld", (long)((NSHTTPURLResponse *)r).statusCode);
                dispatch_semaphore_signal(sem);
            }] resume];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    }
}
