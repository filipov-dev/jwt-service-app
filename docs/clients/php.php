<?php
/**
 * Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
 * токена и массовый отзыв токенов субъекта.
 *
 * Зависимости: composer require spomky-labs/otphp
 *
 * Окружение:
 * - AUTH_TOTP_SECRET — общий TOTP-секрет в base32 (обязательно);
 * - JWT_SERVICE_URL — базовый URL сервиса, по умолчанию http://localhost:8080.
 *
 * ВАЖНО: код считается заново перед каждым запросом. При включённой на сервере
 * защите от переигрывания (AUTH_TOTP_REPLAY_PROTECTION) повторное предъявление
 * того же кода вернёт 401, хотя сам код ещё не истёк.
 *
 * @package JwtServiceClient
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use OTPHP\TOTP;

/**
 * Клиент сервиса выдачи токенов.
 */
final class JwtServiceClient
{
    /**
     * Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
     */
    private const ISSUER_HOST = 'example.com';

    /**
     * @param string $baseUrl Базовый URL сервиса.
     * @param string $secret  Общий TOTP-секрет в base32.
     */
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $secret,
    ) {
    }

    /**
     * Собирает клиент из переменных окружения.
     *
     * @return self
     */
    public static function fromEnv(): self
    {
        return new self(
            getenv('JWT_SERVICE_URL') ?: 'http://localhost:8080',
            getenv('AUTH_TOTP_SECRET') ?: throw new RuntimeException('нужен AUTH_TOTP_SECRET'),
        );
    }

    /**
     * Вычисляет TOTP-код на текущий момент.
     *
     * Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
     *
     * @return string Код из шести десятичных знаков.
     */
    private function totpCode(): string
    {
        return TOTP::createFromSecret($this->secret)->now();
    }

    /**
     * Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
     *
     * @param string            $method HTTP-метод.
     * @param string            $path   Путь ручки, начиная со слеша.
     * @param array<mixed>|null $body   Тело запроса либо null, если тела нет.
     *
     * @return array{status:int, body:string} Код ответа и его тело.
     */
    private function request(string $method, string $path, ?array $body = null): array
    {
        $headers = [
            'X-TOTP-Code: ' . $this->totpCode(),
            'Host: ' . self::ISSUER_HOST,
            'Content-Type: application/json',
        ];

        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'content' => $body === null ? '' : json_encode($body, JSON_THROW_ON_ERROR),
                'ignore_errors' => true,
            ],
        ]);

        $response = file_get_contents($this->baseUrl . $path, false, $context);
        $status = (int) explode(' ', $http_response_header[0])[1];

        return ['status' => $status, 'body' => $response === false ? '' : $response];
    }

    /**
     * Выпускает access-токен (POST /tokens).
     *
     * @param string        $sub         Субъект, которому выдаётся токен.
     * @param list<string>  $aud         Список получателей; не должен быть пустым.
     * @param bool          $withRefresh Запросить refresh для продления сессии.
     *
     * @return array{token:string, refresh_token?:string} Выпущенный токен.
     *
     * @throws RuntimeException 401 — неверный код, 422 — параметры, 500 — JWKS/Redis.
     */
    public function issueToken(string $sub, array $aud, bool $withRefresh = false): array
    {
        $response = $this->request('POST', '/tokens', [
            'sub' => $sub,
            'aud' => $aud,
            'refresh' => $withRefresh,
        ]);

        if ($response['status'] !== 200) {
            throw new RuntimeException("выпуск не удался: {$response['status']}");
        }

        return json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Обменивает refresh-токен на новую пару (POST /tokens/refresh).
     *
     * Старый токен после обмена недействителен: сохраните новый и выбросьте
     * предыдущий.
     *
     * ВНИМАНИЕ: не повторяйте обмен старым токеном при потере ответа. Повторное
     * предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
     * выданные по ним access-токены. Надёжнее выпустить пару заново.
     *
     * @param string $refreshToken Токен из выпуска или прошлого обмена.
     *
     * @return array{token:string, refresh_token:string} Новая пара.
     *
     * @throws RuntimeException 401 — токен неизвестен, истёк или уже использован.
     */
    public function refreshTokens(string $refreshToken): array
    {
        $response = $this->request('POST', '/tokens/refresh', [
            'refresh_token' => $refreshToken,
        ]);

        if ($response['status'] !== 200) {
            throw new RuntimeException("обмен не удался: {$response['status']}");
        }

        return json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Отзывает один токен по его jti (DELETE /tokens/{jti}).
     *
     * Идемпотентно: отзыв несуществующего jti — тоже успех.
     *
     * @param string $jti Идентификатор токена из claim jti.
     *
     * @throws RuntimeException 500 — хранилище недоступно, отзыв НЕ выполнен.
     */
    public function revokeToken(string $jti): void
    {
        $response = $this->request('DELETE', "/tokens/{$jti}");

        if ($response['status'] !== 204) {
            throw new RuntimeException("отзыв не удался: {$response['status']}");
        }
    }

    /**
     * Отзывает все активные токены субъекта.
     *
     * Ручка DELETE /subjects/{sub}/tokens. Нужна при компрометации: гасить токены
     * по одному нельзя, их jti вызывающему неизвестны.
     *
     * @param string $sub Субъект, чьи токены гасятся.
     *
     * @return int Число отозванных токенов; истёкшие не считаются.
     *
     * @throws RuntimeException 500 — хранилище недоступно, отзыв не выполнен.
     */
    public function revokeSubject(string $sub): int
    {
        $response = $this->request('DELETE', "/subjects/{$sub}/tokens");

        if ($response['status'] !== 200) {
            throw new RuntimeException("массовый отзыв не удался: {$response['status']}");
        }

        return json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR)['revoked'];
    }
}

$client = JwtServiceClient::fromEnv();

$issued = $client->issueToken('svc-a', ['svc-b'], true);
echo 'выпущен: ', substr($issued['token'], 0, 32), "...\n";

$refreshed = $client->refreshTokens($issued['refresh_token']);
echo 'обновлён: ', substr($refreshed['token'], 0, 32), "...\n";

echo 'отозвано токенов: ', $client->revokeSubject('svc-a'), "\n";
