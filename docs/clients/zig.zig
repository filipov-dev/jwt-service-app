//! jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
//!
//! Dependencies: standard library only (`std.crypto`, `std.http`).
//!
//! Environment:
//! - `AUTH_TOTP_SECRET` — shared TOTP secret (see the base32 note below);
//! - `JWT_SERVICE_URL` — base URL, default `http://localhost:8080`.
//!
//! This example treats the secret as raw bytes; add a base32 decoder for Google
//! Authenticator compatibility.
//!
//! **The code is recomputed before every request.** With replay protection on
//! (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already
//! seen with `401`, even while that code is still inside its time window.

const std = @import("std");

/// Sent as the Host header and becomes the `iss` claim. Must be the same on
/// issue and on verify, or the token will not verify.
const issuer_host = "example.com";

/// Client errors.
const ClientError = error{
    /// The service replied with an unexpected status.
    UnexpectedStatus,
    /// A required environment variable is missing.
    MissingEnv,
};

/// Computes a fresh TOTP code for right now.
///
/// Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
/// RFC 4226 section 5.3.
///
/// The code is written into `out` (exactly 6 bytes) and returned as a slice.
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

/// Sends a level 3 request.
///
/// `body` is `null` for requests without one (revocation). Returns the HTTP
/// status; the response body is written into `response_buffer`.
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

    // Computed here rather than reused: one code, one request.
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

/// Issues an access token (`POST /tokens`).
///
/// `sub` is the subject (`sub` claim), `aud` the audience (`aud` claim),
/// `with_refresh` also returns a refresh token for extending the session, and
/// `claims_json` carries custom claims as a JSON object (for example
/// `{"role":"admin"}`) or `null`.
///
/// Custom claims sit next to the registered ones, so the consumer reads `role`,
/// not `extra.role`. Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
/// `jti`) give `422` — change lifetime through `ttl`, not `exp`.
///
/// Errors: `401` bad code, `422` bad parameters or forbidden claim, `500` JWKS
/// or Redis unavailable.
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

/// Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
///
/// The old token dies on exchange: store the new one and drop the previous.
///
/// **Never retry** an exchange with the old token when the reply is lost. A
/// second presentation reads as theft, and the server revokes the whole family
/// — refresh tokens and the access tokens issued from them. Issue a new pair
/// instead.
///
/// `401` means the token is unknown, expired or already used.
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

/// Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
///
/// Idempotent: revoking an unknown `jti` is success too. `500` means the store
/// is unreachable and the token is **not** revoked: retry.
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

/// Revokes every active token of a subject.
///
/// Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens cannot
/// be killed one by one because the caller does not know their `jti`. The reply
/// carries a `revoked` field; expired tokens do not count.
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

/// Full token lifecycle: issue, refresh, bulk revoke.
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
