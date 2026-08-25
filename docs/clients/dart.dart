/// jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
///
/// Install: `dart pub add otp http`.
/// Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
/// `http://localhost:8080`).
/// See README.md for endpoints, error codes and client rules.
library;

import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:otp/otp.dart';

/// Client of the token service.
class JwtServiceClient {
  /// Sent as the Host header, becomes the `iss` claim.
  static const issuerHost = 'example.com';

  /// Service base URL.
  final String baseUrl;

  /// Shared TOTP secret, base32.
  final String secret;

  /// Creates a client.
  JwtServiceClient(this.baseUrl, this.secret);

  /// Builds a client from the environment.
  factory JwtServiceClient.fromEnv() {
    final secret = Platform.environment['AUTH_TOTP_SECRET'];
    if (secret == null) throw StateError('AUTH_TOTP_SECRET is required');

    return JwtServiceClient(
      Platform.environment['JWT_SERVICE_URL'] ?? 'http://localhost:8080',
      secret,
    );
  }

  /// Fresh TOTP code: SHA-1, 6 digits, 30-second step.
  String _totpCode() => OTP.generateTOTPCodeString(
        secret,
        DateTime.now().millisecondsSinceEpoch,
        length: 6,
        interval: 30,
        algorithm: Algorithm.SHA1,
        isGoogle: true,
      );

  /// Headers with a code computed right before the call.
  Map<String, String> _headers() => {
        'X-TOTP-Code': _totpCode(),
        'Host': issuerHost,
        'Content-Type': 'application/json',
      };

  /// `POST /tokens`
  ///
  /// [sub] subject, [aud] audience, [withRefresh] also ask for a refresh token,
  /// [claims] custom claims.
  ///
  /// Returns `{"token": ..., "refresh_token": ...}`.
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

  /// `POST /tokens/refresh` — returns a new pair; the old refresh token is dead
  /// once the call succeeds.
  ///
  /// [refreshToken] token from an issue or a previous refresh.
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

  /// `DELETE /tokens/{jti}` — idempotent.
  Future<void> revokeToken(String jti) async {
    final response = await http.delete(
      Uri.parse('$baseUrl/tokens/$jti'),
      headers: _headers(),
    );

    if (response.statusCode != 204) {
      throw HttpException('revoke failed: ${response.statusCode}');
    }
  }

  /// `DELETE /subjects/{sub}/tokens` — returns the number of revoked tokens.
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

/// Issue -> refresh -> revoke.
Future<void> main() async {
  final client = JwtServiceClient.fromEnv();

  final issued = await client.issueToken('svc-a', ['svc-b'],
      withRefresh: true, claims: {'role': 'admin'});
  print('issued: ${issued['token'].toString().substring(0, 32)}...');

  final refreshed = await client.refreshTokens(issued['refresh_token'] as String);
  print('refreshed: ${refreshed['token'].toString().substring(0, 32)}...');

  print('revoked: ${await client.revokeSubject('svc-a')}');
}
