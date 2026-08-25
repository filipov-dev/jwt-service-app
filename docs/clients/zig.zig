//! jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//!
//! Dependencies: standard library only (`std.crypto`, `std.http`).
//!
//! Env: `AUTH_TOTP_SECRET` (raw bytes here, see README.md), `JWT_SERVICE_URL`
//! (default `http://localhost:8080`).
//!
//! See README.md for endpoints, error codes and client rules.

const std = @import("std");

/// Sent as the Host header, becomes the `iss` claim.
const issuer_host = "example.com";

/// Client errors.
const ClientError = error{
    /// The service replied with an unexpected status.
    UnexpectedStatus,
    /// A required environment variable is missing.
    MissingEnv,
};

/// Fresh TOTP code: SHA-1, 6 digits, 30-second step.
///
/// Truncation follows RFC 4226 section 5.3. The code is written into `out`
/// (exactly 6 bytes) and returned as a slice.
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

/// Sends a level 3 request with a code computed right before the call.
///
/// `body` is `null` for requests without one. Returns the HTTP status; the
/// response body is written into `response_buffer`.
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

/// `POST /tokens`
///
/// `claims_json` carries custom claims as a JSON object, or `null`.
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

/// `POST /tokens/refresh` — returns a new pair; the old refresh token is dead
/// once the call succeeds.
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

/// `DELETE /tokens/{jti}` — idempotent.
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

/// `DELETE /subjects/{sub}/tokens` — the reply carries a `revoked` field.
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

/// Issue -> refresh -> revoke.
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var response = std.ArrayList(u8).init(allocator);
    defer response.deinit();

    try issueToken(allocator, "svc-a", "svc-b", true, "{\"role\":\"admin\"}", &response);
    std.debug.print("issued: {s}\n", .{response.items});

    // Real code should parse the JSON with std.json and take refresh_token.
    response.clearRetainingCapacity();
    try revokeSubject(allocator, "svc-a", &response);
    std.debug.print("bulk revoke: {s}\n", .{response.items});
}
