//! Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
//!
//! Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
//! токена и массовый отзыв токенов субъекта.
//!
//! Зависимости: только стандартная библиотека (`std.crypto`, `std.http`).
//!
//! Окружение:
//! - `AUTH_TOTP_SECRET` — общий TOTP-секрет (см. примечание о base32);
//! - `JWT_SERVICE_URL` — базовый URL, по умолчанию `http://localhost:8080`.
//!
//! Пример трактует секрет как сырые байты; для совместимости с Google
//! Authenticator добавьте декодер base32.
//!
//! **Код считается заново перед каждым запросом.** При включённой на сервере
//! защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное
//! предъявление того же кода вернёт `401`, хотя сам код ещё не истёк.

const std = @import("std");

/// Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
const issuer_host = "example.com";

/// Ошибки клиента.
const ClientError = error{
    /// Сервис ответил неожиданным кодом.
    UnexpectedStatus,
    /// Не задана обязательная переменная окружения.
    MissingEnv,
};

/// Вычисляет TOTP-код на текущий момент.
///
/// Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
/// Усечение — по RFC 4226 §5.3.
///
/// Результат пишется в `out` (ровно 6 байт) и возвращается срезом.
fn totpCode(secret: []const u8, out: *[6]u8) []const u8 {
    const counter: u64 = @intCast(@divFloor(std.time.timestamp(), 30));

    var message: [8]u8 = undefined;
    std.mem.writeInt(u64, &message, counter, .big);

    var digest: [std.crypto.auth.hmac.HmacSha1.mac_length]u8 = undefined;
    std.crypto.auth.hmac.HmacSha1.create(&digest, &message, secret);

    const offset: usize = digest[digest.len - 1] & 0x0f;
    const code: u32 = (@as(u32, digest[offset] & 0x7f) << 24) |
        (@as(u32, digest[offset + 1]) << 16) |
        (@as(u32, digest[offset + 2]) << 8) |
        @as(u32, digest[offset + 3]);

    _ = std.fmt.bufPrint(out, "{d:0>6}", .{code % 1_000_000}) catch unreachable;
    return out;
}

/// Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
///
/// `body` — тело запроса либо `null` для запросов без него (отзыв).
/// Возвращает HTTP-код ответа; тело пишется в `response_buffer`.
fn request(
    allocator: std.mem.Allocator,
    method: std.http.Method,
    path: []const u8,
    body: ?[]const u8,
    response_buffer: *std.ArrayList(u8),
) !u16 {
    const service = std.posix.getenv("JWT_SERVICE_URL") orelse "http://localhost:8080";
    const secret = std.posix.getenv("AUTH_TOTP_SECRET") orelse return ClientError.MissingEnv;

    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ service, path });
    defer allocator.free(url);

    // Код считается здесь, а не переиспользуется: один код — один запрос.
    var code_buffer: [6]u8 = undefined;
    const code = totpCode(secret, &code_buffer);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const result = try client.fetch(.{
        .method = method,
        .location = .{ .url = url },
        .extra_headers = &.{
            .{ .name = "X-TOTP-Code", .value = code },
            .{ .name = "Host", .value = issuer_host },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .payload = body,
        .response_storage = .{ .dynamic = response_buffer },
    });

    return @intFromEnum(result.status);
}

/// Выпускает access-токен (`POST /tokens`).
///
/// `sub` — субъект (claim `sub`), `aud` — получатель (claim `aud`),
/// `with_refresh` — запросить refresh-токен для продления сессии,
/// `claims_json` — произвольные claims JSON-объектом (например
/// `{"role":"admin"}`) либо `null`.
///
/// Произвольные claims попадают в payload рядом с зарегистрированными. Служебные
/// имена (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) переопределять нельзя —
/// сервис ответит `422`.
///
/// Ошибки: `401` — неверный код, `422` — некорректные параметры или запрещённый
/// claim, `500` — недоступны JWKS или Redis.
pub fn issueToken(
    allocator: std.mem.Allocator,
    sub: []const u8,
    aud: []const u8,
    with_refresh: bool,
    claims_json: ?[]const u8,
    response: *std.ArrayList(u8),
) !void {
    const claims_part = if (claims_json) |json|
        try std.fmt.allocPrint(allocator, ",\"claims\":{s}", .{json})
    else
        try allocator.dupe(u8, "");
    defer allocator.free(claims_part);

    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"sub\":\"{s}\",\"aud\":[\"{s}\"],\"refresh\":{}{s}}}",
        .{ sub, aud, with_refresh, claims_part },
    );
    defer allocator.free(body);

    const status = try request(allocator, .POST, "/tokens", body, response);
    if (status != 200) return ClientError.UnexpectedStatus;
}

/// Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
///
/// Старый токен после обмена недействителен: сохраните новый и выбросьте
/// предыдущий.
///
/// **Внимание:** не повторяйте обмен старым токеном при потере ответа. Повторное
/// предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
/// выданные по ним access-токены. Надёжнее выпустить пару заново.
///
/// Ошибка при `401`: токен неизвестен, истёк или уже использован.
pub fn refreshTokens(
    allocator: std.mem.Allocator,
    refresh_token: []const u8,
    response: *std.ArrayList(u8),
) !void {
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"refresh_token\":\"{s}\"}}",
        .{refresh_token},
    );
    defer allocator.free(body);

    const status = try request(allocator, .POST, "/tokens/refresh", body, response);
    if (status != 200) return ClientError.UnexpectedStatus;
}

/// Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
///
/// Идемпотентно: отзыв несуществующего `jti` — тоже успех. Ошибка при `500`
/// означает, что хранилище недоступно и отзыв **не выполнен**.
pub fn revokeToken(
    allocator: std.mem.Allocator,
    jti: []const u8,
    response: *std.ArrayList(u8),
) !void {
    const path = try std.fmt.allocPrint(allocator, "/tokens/{s}", .{jti});
    defer allocator.free(path);

    const status = try request(allocator, .DELETE, path, null, response);
    if (status != 204) return ClientError.UnexpectedStatus;
}

/// Отзывает все активные токены субъекта.
///
/// Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить токены
/// по одному нельзя, их `jti` вызывающему неизвестны. В теле ответа — поле
/// `revoked`; истёкшие токены не считаются.
pub fn revokeSubject(
    allocator: std.mem.Allocator,
    sub: []const u8,
    response: *std.ArrayList(u8),
) !void {
    const path = try std.fmt.allocPrint(allocator, "/subjects/{s}/tokens", .{sub});
    defer allocator.free(path);

    const status = try request(allocator, .DELETE, path, null, response);
    if (status != 200) return ClientError.UnexpectedStatus;
}

/// Демонстрирует полный жизненный цикл токена.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var response = std.ArrayList(u8).init(allocator);
    defer response.deinit();

    try issueToken(allocator, "svc-a", "svc-b", true, "{\"role\":\"admin\"}", &response);
    std.debug.print("выпущен: {s}\n", .{response.items});

    // В боевом коде разберите JSON через std.json и достаньте refresh_token.
    response.clearRetainingCapacity();
    try revokeSubject(allocator, "svc-a", &response);
    std.debug.print("массовый отзыв: {s}\n", .{response.items});
}
