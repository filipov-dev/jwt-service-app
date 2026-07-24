// Dart — библиотека: otp (`dart pub add otp http`)
import 'dart:io';
import 'package:otp/otp.dart';
import 'package:http/http.dart' as http;

Future<void> main() async {
  final secret = Platform.environment['AUTH_TOTP_SECRET']!;            // base32
  final service = Platform.environment['JWT_SERVICE_URL'] ?? 'http://localhost:8080';

  final code = OTP.generateTOTPCodeString(
      secret, DateTime.now().millisecondsSinceEpoch,
      length: 6, interval: 30, algorithm: Algorithm.SHA1, isGoogle: true);

  final resp = await http.post(Uri.parse('$service/tokens'),
      headers: {'X-TOTP-Code': code, 'Host': 'example.com', 'Content-Type': 'application/json'},
      body: '{"sub":"svc-a","aud":["svc-b"]}');
  print('${resp.statusCode} ${resp.body}');
}
