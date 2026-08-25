/// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
///
/// Install: `dart pub add otp http`.
///
/// Env:
/// * `AUTH_TOTP_SECRET` — shared TOTP secret, base32 (required);
/// * `JWT_SERVICE_URL` — service base URL, default `http://localhost:8080`.
///
/// The code is recomputed **before every request**. With replay protection on
/// (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already seen
/// with `401`, even while that code is still inside its time window.
library;

import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:otp/otp.dart';

/// Client of the token service, covering all four level 3 endpoints.
class JwtServiceClient {
  /// Sent as the Host header and becomes the `iss` claim. Must be the same on
  /// issue and on verify, or the token will not verify.
  static const issuerHost = 'example.com';

  /// Service base URL.
  final String baseUrl;

  /// Shared TOTP secret, base32.
  final String secret;

  /// Creates a client.
  JwtServiceClient(this.baseUrl, this.secret);

  /// Builds a client from the environment.
  ///
  /// Throws [StateError] if `AUTH_TOTP_SECRET` is not set.
  factory JwtServiceClient.fromEnv() {
    final secret = Platform.environment['AUTH_TOTP_SECRET'];
    if (secret == null) throw StateError('AUTH_TOTP_SECRET is required');

    return JwtServiceClient(
      Platform.environment['JWT_SERVICE_URL'] ?? 'http://localhost:8080',
      secret,
    );
  }

  /// Fresh code for right now: SHA-1, 6 digits, 30-second step.
  String _totpCode() => OTP.generateTOTPCodeString(
        secret,
        DateTime.now().millisecondsSinceEpoch,
        length: 6,
        interval: 30,
        algorithm: Algorithm.SHA1,
        isGoogle: true,
      );

  /// Headers with a code computed here, not reused: one code, one request.
  Map<String, String> _headers() => {
        'X-TOTP-Code': _totpCode(),
        'Host': issuerHost,
        'Content-Type': 'application/json',
      };

  /// Issues an access token (`POST /tokens`).
  ///
  /// [sub] is the subject (`sub` claim), [aud] the audience (`aud` claim, must
  /// not be empty), [withRefresh] also returns a refresh token for extending
  /// the session, and [claims] are custom values (role, scope, tenant) placed
  /// next to the registered ones, so the consumer reads `role`, not
  /// `extra.role`.
  ///
  /// Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) are
  /// rejected with `422` — change lifetime through `ttl`, not `exp`. Count and
  /// size are capped server-side.
  ///
  /// Returns `{"token": ..., "refresh_token": ...}`; `refresh_token` is present
  /// only if it was requested.
  ///
  /// Throws [HttpException]: `401` bad code, `422` bad parameters or forbidden
  /// claim, `500` JWKS or Redis unavailable.
  Future<Map<String, dynamic>> issueToken(
    String sub,
    List<String> aud, {
    bool withRefresh = false,
    Map<String, dynamic> claims = const {},
  }) async {
    final body = <String, dynamic>{'sub': sub, 'aud': aud, 'refresh': withRefresh};
    if (claims.isNotEmpty) body['claims'] = claims;

    final response = await http.post(
      Uri.parse('$baseUrl/tokens'),
      headers: _headers(),
      body: jsonEncode(body),
    );

    if (response.statusCode != 200) {
      throw HttpException('issue failed: ${response.statusCode}');
    }

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Exchanges a refresh token for a new pair (`POST /tokens/refresh`).
  ///
  /// The old token dies on exchange: store the new one and drop the previous.
  ///
  /// **Never retry** an exchange with the old token when the reply is lost. A
  /// second presentation reads as theft, and the server revokes the whole
  /// family — refresh tokens and the access tokens issued from them. Issue a
  /// new pair instead.
  ///
  /// [refreshToken] comes from an issue or a previous exchange.
  ///
  /// Throws [HttpException]: `401` — token unknown, expired or already used.
  Future<Map<String, dynamic>> refreshTokens(String refreshToken) async {
    final response = await http.post(
      Uri.parse('$baseUrl/tokens/refresh'),
      headers: _headers(),
      body: jsonEncode({'refresh_token': refreshToken}),
    );

    if (response.statusCode != 200) {
      throw HttpException('refresh failed: ${response.statusCode}');
    }

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Revokes one token by its `jti` (`DELETE /tokens/{jti}`).
  ///
  /// Idempotent: revoking an unknown [jti] is success too — the desired state
  /// holds either way.
  ///
  /// Throws [HttpException]: `500` — store unreachable, the token is **not**
  /// revoked; retry.
  Future<void> revokeToken(String jti) async {
    final response = await http.delete(
      Uri.parse('$baseUrl/tokens/$jti'),
      headers: _headers(),
    );

    if (response.statusCode != 204) {
      throw HttpException('revoke failed: ${response.statusCode}');
    }
  }

  /// Revokes every active token of a subject.
  ///
  /// Endpoint `DELETE /subjects/{sub}/tokens`. The compromise path: tokens
  /// cannot be killed one by one because the caller does not know their `jti`.
  ///
  /// Returns the number of revoked tokens; expired ones do not count.
  Future<int> revokeSubject(String sub) async {
    final response = await http.delete(
      Uri.parse('$baseUrl/subjects/$sub/tokens'),
      headers: _headers(),
    );

    if (response.statusCode != 200) {
      throw HttpException('bulk revoke failed: ${response.statusCode}');
    }

    return (jsonDecode(response.body) as Map<String, dynamic>)['revoked'] as int;
  }
}

/// Full token lifecycle: issue, refresh, bulk revoke.
Future<void> main() async {
  final client = JwtServiceClient.fromEnv();

  final issued = await client.issueToken('svc-a', ['svc-b'],
      withRefresh: true, claims: {'role': 'admin'});
  print('issued: ${issued['token'].toString().substring(0, 32)}...');

  final refreshed = await client.refreshTokens(issued['refresh_token'] as String);
  print('refreshed: ${refreshed['token'].toString().substring(0, 32)}...');

  print('revoked: ${await client.revokeSubject('svc-a')}');
}
