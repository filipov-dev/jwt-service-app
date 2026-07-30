/// Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
///
/// Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
/// токена и массовый отзыв токенов субъекта.
///
/// Зависимости: `dart pub add otp http`.
///
/// Окружение:
/// * `AUTH_TOTP_SECRET` — общий TOTP-секрет в base32 (обязательно);
/// * `JWT_SERVICE_URL` — базовый URL сервиса, по умолчанию `http://localhost:8080`.
///
/// Код считается **заново перед каждым запросом**. При включённой на сервере
/// защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное
/// предъявление того же кода вернёт `401`, хотя сам код ещё не истёк.
library;

import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:otp/otp.dart';

/// Клиент сервиса выдачи токенов.
class JwtServiceClient {
  /// Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
  static const issuerHost = 'example.com';

  /// Базовый URL сервиса.
  final String baseUrl;

  /// Общий TOTP-секрет в base32.
  final String secret;

  /// Создаёт клиент.
  JwtServiceClient(this.baseUrl, this.secret);

  /// Собирает клиент из переменных окружения.
  ///
  /// Бросает [StateError], если не задан `AUTH_TOTP_SECRET`.
  factory JwtServiceClient.fromEnv() {
    final secret = Platform.environment['AUTH_TOTP_SECRET'];
    if (secret == null) throw StateError('нужен AUTH_TOTP_SECRET');

    return JwtServiceClient(
      Platform.environment['JWT_SERVICE_URL'] ?? 'http://localhost:8080',
      secret,
    );
  }

  /// Вычисляет TOTP-код на текущий момент.
  ///
  /// Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
  ///
  /// Возвращает код из шести десятичных знаков.
  String _totpCode() => OTP.generateTOTPCodeString(
        secret,
        DateTime.now().millisecondsSinceEpoch,
        length: 6,
        interval: 30,
        algorithm: Algorithm.SHA1,
        isGoogle: true,
      );

  /// Заголовки для запроса к ручке уровня 3 со свежим TOTP-кодом.
  Map<String, String> _headers() => {
        // Код считается здесь, а не переиспользуется: один код — один запрос.
        'X-TOTP-Code': _totpCode(),
        'Host': issuerHost,
        'Content-Type': 'application/json',
      };

  /// Выпускает access-токен (`POST /tokens`).
  ///
  /// [sub] — субъект (claim `sub`), [aud] — список получателей (claim `aud`,
  /// не пустой), [withRefresh] — запросить refresh-токен для продления сессии,
  /// [claims] — произвольные claims (роли, scope, tenant), попадают в payload
  /// рядом с зарегистрированными.
  ///
  /// Служебные имена (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`)
  /// переопределять нельзя — сервис ответит `422`. Число ключей и объём
  /// ограничены на сервере.
  ///
  /// Возвращает `{"token": ..., "refresh_token": ...}`; `refresh_token`
  /// присутствует, только если запрашивался.
  ///
  /// Бросает [HttpException]: `401` — неверный код, `422` — параметры,
  /// `500` — недоступны JWKS или Redis.
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
      throw HttpException('выпуск не удался: ${response.statusCode}');
    }

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
  ///
  /// Старый токен после обмена недействителен: сохраните новый и выбросьте
  /// предыдущий.
  ///
  /// **Внимание:** не повторяйте обмен старым токеном при потере ответа.
  /// Повторное предъявление трактуется как кража и гасит всю семью — и
  /// refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
  /// заново.
  ///
  /// [refreshToken] — токен из выпуска или прошлого обмена.
  ///
  /// Бросает [HttpException]: `401` — токен неизвестен, истёк или использован.
  Future<Map<String, dynamic>> refreshTokens(String refreshToken) async {
    final response = await http.post(
      Uri.parse('$baseUrl/tokens/refresh'),
      headers: _headers(),
      body: jsonEncode({'refresh_token': refreshToken}),
    );

    if (response.statusCode != 200) {
      throw HttpException('обмен не удался: ${response.statusCode}');
    }

    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  /// Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
  ///
  /// Идемпотентно: отзыв несуществующего [jti] — тоже успех.
  ///
  /// Бросает [HttpException]: `500` — хранилище недоступно, отзыв **не
  /// выполнен**, попытку следует повторить.
  Future<void> revokeToken(String jti) async {
    final response = await http.delete(
      Uri.parse('$baseUrl/tokens/$jti'),
      headers: _headers(),
    );

    if (response.statusCode != 204) {
      throw HttpException('отзыв не удался: ${response.statusCode}');
    }
  }

  /// Отзывает все активные токены субъекта.
  ///
  /// Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить
  /// токены по одному нельзя, их `jti` вызывающему неизвестны.
  ///
  /// Возвращает число отозванных токенов; истёкшие не считаются.
  Future<int> revokeSubject(String sub) async {
    final response = await http.delete(
      Uri.parse('$baseUrl/subjects/$sub/tokens'),
      headers: _headers(),
    );

    if (response.statusCode != 200) {
      throw HttpException('массовый отзыв не удался: ${response.statusCode}');
    }

    return (jsonDecode(response.body) as Map<String, dynamic>)['revoked'] as int;
  }
}

/// Демонстрирует полный жизненный цикл токена.
Future<void> main() async {
  final client = JwtServiceClient.fromEnv();

  final issued = await client.issueToken('svc-a', ['svc-b'],
      withRefresh: true, claims: {'role': 'admin'});
  print('выпущен: ${issued['token'].toString().substring(0, 32)}...');

  final refreshed = await client.refreshTokens(issued['refresh_token'] as String);
  print('обновлён: ${refreshed['token'].toString().substring(0, 32)}...');

  print('отозвано токенов: ${await client.revokeSubject('svc-a')}');
}
