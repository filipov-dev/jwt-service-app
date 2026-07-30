// Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
//
// Зависимости: SwiftOTP (SPM).
//
// Окружение:
//   AUTH_TOTP_SECRET — общий TOTP-секрет в base32 (обязательно);
//   JWT_SERVICE_URL  — базовый URL сервиса, по умолчанию http://localhost:8080.

import Foundation
import SwiftOTP

/// Ответ на выпуск токена или обмен refresh-токена.
struct TokenResponse: Decodable {
    /// Подписанный JWT в формате `header.payload.signature`.
    let token: String
    /// Refresh-токен; присутствует, только если запрашивался.
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case token
        case refreshToken = "refresh_token"
    }
}

/// Ответ на массовый отзыв токенов субъекта.
struct RevokeGroupResponse: Decodable {
    /// Сколько активных токенов отозвано; истёкшие не считаются.
    let revoked: Int
}

/// Ошибки клиента.
enum ClientError: Error {
    /// Сервис ответил неожиданным кодом.
    case unexpectedStatus(Int)
    /// Не удалось посчитать TOTP-код.
    case totpFailed
}

/// Клиент сервиса выдачи токенов, покрывающий все четыре ручки уровня 3.
///
/// - Important: TOTP-код считается **заново перед каждым запросом**. При
///   включённой на сервере защите от переигрывания
///   (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление того же кода вернёт
///   `401`, хотя сам код ещё не истёк.
struct JwtServiceClient {

    /// Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
    private static let issuerHost = "example.com"

    private let baseURL: String
    private let totp: TOTP

    /// Создаёт клиент.
    ///
    /// - Parameters:
    ///   - baseURL: базовый URL сервиса.
    ///   - secret: общий TOTP-секрет в base32.
    init?(baseURL: String, secret: String) {
        guard let data = base32DecodeToData(secret),
              // Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, 30 с.
              let totp = TOTP(secret: data, digits: 6, timeInterval: 30, algorithm: .sha1)
        else { return nil }

        self.baseURL = baseURL
        self.totp = totp
    }

    /// Вычисляет TOTP-код на текущий момент.
    ///
    /// - Returns: код из шести десятичных знаков.
    /// - Throws: ``ClientError/totpFailed`` при сбое генератора.
    private func totpCode() throws -> String {
        guard let code = totp.generate(time: Date()) else { throw ClientError.totpFailed }
        return code
    }

    /// Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
    ///
    /// - Parameters:
    ///   - method: HTTP-метод.
    ///   - path: путь ручки, начиная со слеша.
    ///   - body: тело запроса либо `nil`, если тела нет.
    /// - Returns: тело ответа и его HTTP-код.
    private func request(
        _ method: String,
        _ path: String,
        body: [String: Any]? = nil
    ) async throws -> (Data, Int) {
        var request = URLRequest(url: URL(string: baseURL + path)!)
        request.httpMethod = method

        // Код считается здесь, а не переиспользуется: один код — один запрос.
        request.setValue(try totpCode(), forHTTPHeaderField: "X-TOTP-Code")
        request.setValue(Self.issuerHost, forHTTPHeaderField: "Host")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0

        return (data, status)
    }

    /// Выпускает access-токен (`POST /tokens`).
    ///
    /// - Parameters:
    ///   - sub: субъект, которому выдаётся токен (claim `sub`).
    ///   - aud: список получателей (claim `aud`); не должен быть пустым.
    ///   - withRefresh: запросить refresh-токен для продления сессии.
    ///   - claims: произвольные claims (роли, scope, tenant) — попадают в payload
    ///     рядом с зарегистрированными. Служебные имена (`iss`, `sub`, `aud`,
    ///     `exp`, `iat`, `nbf`, `jti`) переопределять нельзя: сервис ответит
    ///     `422`. Число ключей и объём ограничены на сервере.
    /// - Returns: выпущенный токен и, если запрашивался, refresh-токен.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `401` неверный код,
    ///   `422` некорректные параметры или запрещённый claim, `500` недоступны
    ///   JWKS или Redis.
    func issueToken(
        sub: String,
        aud: [String],
        withRefresh: Bool = false,
        claims: [String: Any] = [:]
    ) async throws -> TokenResponse {
        var body: [String: Any] = ["sub": sub, "aud": aud, "refresh": withRefresh]
        if !claims.isEmpty { body["claims"] = claims }

        let (data, status) = try await request("POST", "/tokens", body: body)

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    /// Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
    ///
    /// Старый токен после обмена недействителен: сохраните новый и выбросьте
    /// предыдущий.
    ///
    /// - Warning: не повторяйте обмен старым токеном при потере ответа.
    ///   Повторное предъявление трактуется как кража и гасит всю семью — и
    ///   refresh-токены, и выданные по ним access-токены. Надёжнее выпустить
    ///   пару заново.
    ///
    /// - Parameter refreshToken: токен из выпуска или прошлого обмена.
    /// - Returns: новая пара access + refresh.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `401`, если токен
    ///   неизвестен, истёк или уже использован.
    func refreshTokens(_ refreshToken: String) async throws -> TokenResponse {
        let (data, status) = try await request(
            "POST", "/tokens/refresh",
            body: ["refresh_token": refreshToken]
        )

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(TokenResponse.self, from: data)
    }

    /// Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
    ///
    /// Идемпотентно: отзыв несуществующего `jti` — тоже успех.
    ///
    /// - Parameter jti: идентификатор токена из claim `jti`.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `500`, хранилище
    ///   недоступно и отзыв **не выполнен**: повторите попытку.
    func revokeToken(_ jti: String) async throws {
        let (_, status) = try await request("DELETE", "/tokens/\(jti)")
        guard status == 204 else { throw ClientError.unexpectedStatus(status) }
    }

    /// Отзывает все активные токены субъекта.
    ///
    /// Ручка `DELETE /subjects/{sub}/tokens`. Нужна при компрометации: гасить
    /// токены по одному нельзя, их `jti` вызывающему неизвестны.
    ///
    /// - Parameter sub: субъект, чьи токены гасятся.
    /// - Returns: число отозванных токенов; истёкшие не считаются.
    /// - Throws: ``ClientError/unexpectedStatus(_:)`` — `500`, отзыв не выполнен.
    func revokeSubject(_ sub: String) async throws -> Int {
        let (data, status) = try await request("DELETE", "/subjects/\(sub)/tokens")

        guard status == 200 else { throw ClientError.unexpectedStatus(status) }
        return try JSONDecoder().decode(RevokeGroupResponse.self, from: data).revoked
    }
}

// Демонстрация полного жизненного цикла токена.
let service = ProcessInfo.processInfo.environment["JWT_SERVICE_URL"] ?? "http://localhost:8080"
let secret = ProcessInfo.processInfo.environment["AUTH_TOTP_SECRET"]!

guard let client = JwtServiceClient(baseURL: service, secret: secret) else {
    fatalError("некорректный AUTH_TOTP_SECRET")
}

let issued = try await client.issueToken(
    sub: "svc-a", aud: ["svc-b"], withRefresh: true, claims: ["role": "admin"])
print("выпущен:", issued.token.prefix(32), "...")

let refreshed = try await client.refreshTokens(issued.refreshToken!)
print("обновлён:", refreshed.token.prefix(32), "...")

print("отозвано токенов:", try await client.revokeSubject("svc-a"))
