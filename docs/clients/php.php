<?php
/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Install: composer require spomky-labs/otphp
 * Env: AUTH_TOTP_SECRET (base32), JWT_SERVICE_URL (default http://localhost:8080).
 * See README.md for endpoints, error codes and client rules.
 *
 * @package JwtServiceClient
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use OTPHP\TOTP;

/**
 * Client of the token service.
 */
final class JwtServiceClient
{
    /**
     * Sent as the Host header, becomes the `iss` claim.
     */
    private const ISSUER_HOST = 'example.com';

    /**
     * @param string $baseUrl Service base URL.
     * @param string $secret  Shared TOTP secret, base32.
     */
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $secret,
    ) {
    }

    /**
     * Builds a client from the environment.
     *
     * @return self
     */
    public static function fromEnv(): self
    {
        return new self(
            getenv('JWT_SERVICE_URL') ?: 'http://localhost:8080',
            getenv('AUTH_TOTP_SECRET') ?: throw new RuntimeException('AUTH_TOTP_SECRET is required'),
        );
    }

    /**
     * Fresh TOTP code: SHA-1, 6 digits, 30-second step.
     *
     * @return string
     */
    private function totpCode(): string
    {
        return TOTP::createFromSecret($this->secret)->now();
    }

    /**
     * Sends a level 3 request with a code computed right before the call.
     *
     * @param string            $method HTTP method.
     * @param string            $path   Endpoint path.
     * @param array<mixed>|null $body   Request body, if any.
     *
     * @return array{status:int, body:string}
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
     * POST /tokens
     *
     * @param string              $sub
     * @param list<string>        $aud
     * @param bool                $withRefresh
     * @param array<string,mixed> $claims
     *
     * @return array{token:string, refresh_token?:string}
     */
    public function issueToken(
        string $sub,
        array $aud,
        bool $withRefresh = false,
        array $claims = [],
    ): array {
        $body = ['sub' => $sub, 'aud' => $aud, 'refresh' => $withRefresh];
        if ($claims !== []) {
            $body['claims'] = $claims;
        }

        $response = $this->request('POST', '/tokens', $body);

        if ($response['status'] !== 200) {
            throw new RuntimeException("issue failed: {$response['status']}");
        }

        return json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * POST /tokens/refresh — returns a new pair; the old refresh token is dead.
     *
     * @param string $refreshToken
     *
     * @return array{token:string, refresh_token:string}
     */
    public function refreshTokens(string $refreshToken): array
    {
        $response = $this->request('POST', '/tokens/refresh', [
            'refresh_token' => $refreshToken,
        ]);

        if ($response['status'] !== 200) {
            throw new RuntimeException("refresh failed: {$response['status']}");
        }

        return json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * DELETE /tokens/{jti} — idempotent.
     *
     * @param string $jti
     */
    public function revokeToken(string $jti): void
    {
        $response = $this->request('DELETE', "/tokens/{$jti}");

        if ($response['status'] !== 204) {
            throw new RuntimeException("revoke failed: {$response['status']}");
        }
    }

    /**
     * DELETE /subjects/{sub}/tokens
     *
     * @param string $sub
     *
     * @return int Number of revoked tokens.
     */
    public function revokeSubject(string $sub): int
    {
        $response = $this->request('DELETE', "/subjects/{$sub}/tokens");

        if ($response['status'] !== 200) {
            throw new RuntimeException("bulk revoke failed: {$response['status']}");
        }

        return json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR)['revoked'];
    }
}

$client = JwtServiceClient::fromEnv();

$issued = $client->issueToken('svc-a', ['svc-b'], true, ['role' => 'admin']);
echo 'issued: ', substr($issued['token'], 0, 32), "...\n";

$refreshed = $client->refreshTokens($issued['refresh_token']);
echo 'refreshed: ', substr($refreshed['token'], 0, 32), "...\n";

echo 'revoked: ', $client->revokeSubject('svc-a'), "\n";
