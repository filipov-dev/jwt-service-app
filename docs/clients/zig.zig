// Zig — TOTP через std.crypto HMAC-SHA1 (без внешних зависимостей).
// AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (для base32 добавьте декодер).
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    const secret = try std.process.getEnvVarOwned(alloc, "AUTH_TOTP_SECRET");
    const counter: u64 = @intCast(@divFloor(std.time.timestamp(), 30));

    var msg: [8]u8 = undefined;
    std.mem.writeInt(u64, &msg, counter, .big);

    const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
    var hs: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&hs, &msg, secret);

    const off = hs[hs.len - 1] & 0x0f;
    const bin = (@as(u32, hs[off] & 0x7f) << 24) | (@as(u32, hs[off + 1]) << 16) |
        (@as(u32, hs[off + 2]) << 8) | @as(u32, hs[off + 3]);
    const code = bin % 1_000_000;

    // Готовый 6-значный код в `code`; отправьте его заголовком X-TOTP-Code,
    // напр. через std.http.Client, в POST $JWT_SERVICE_URL/tokens.
    std.debug.print("{d:0>6}\n", .{code});
}
