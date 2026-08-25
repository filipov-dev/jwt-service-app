<?php
/**
 * jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Install: composer require spomky-labs/otphp
 *
 * Env:
 * - AUTH_TOTP_SECRET — shared TOTP secret, base32 (required);
 * - JWT_SERVICE_URL — service base URL, default http://localhost:8080.
 *
 * The code is recomputed before every request. With replay protection on
 * (AUTH_TOTP_REPLAY_PROTECTION) the server rejects a code it has already seen
 * with 401, even while that code is still inside its time window.
 *
 * @package JwtServiceClient
 */

declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use OTPHP\TOTP;

/**
 * Client of the token service, covering all four level 3 endpoints.
 */
final class JwtServiceClient
{
    /**
     * Sent as the Host header and becomes the `iss` claim. Must be the same on
     * issue and on verify, or the token will not verify.
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
     * Fresh code for right now: SHA-1, 6 digits, 30-second step.
     *
     * @return string Six decimal digits.
     */
    private function totpCode(): string
    {
        return TOTP::createFromSecret($this->secret)->now();
    }

    /**
     * Sends a level 3 request. The code is computed here rather than reused:
     * one code, one request.
     *
     * @param string            $method HTTP method.
     * @param string            $path   Endpoint path.
     * @param array<mixed>|null $body   Request body, or null when there is none.
     *
     * @return array{status:int, body:string} Status and response body.
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
     * Issues an access token (POST /tokens).
     *
     * @param string              $sub         Subject the token is issued to.
     * @param list<string>        $aud         Audience; must not be empty.
     * @param bool                $withRefresh Also return a refresh token for
     *                                         extending the session.
     * @param array<string,mixed> $claims      Custom claims (role, scope,
     *                                         tenant): they sit next to the
     *                                         registered ones, so the consumer
     *                                         reads role, not extra.role.
     *                                         Reserved names (iss, sub, aud,
     *                                         exp, iat, nbf, jti) give 422 —
     *                                         change lifetime through ttl, not
     *                                         exp. Count and size are capped
     *                                         server-side.
     *
     * @return array{token:string, refresh_token?:string} The issued token.
     *
     * @throws RuntimeException 401 bad code, 422 bad parameters or forbidden
     *                          claim, 500 JWKS or Redis unavailable.
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
     * Exchanges a refresh token for a new pair (POST /tokens/refresh).
     *
     * The old token dies on exchange: store the new one and drop the previous.
     *
     * Never retry an exchange with the old token when the reply is lost. A
     * second presentation reads as theft, and the server revokes the whole
     * family — refresh tokens and the access tokens issued from them. Issue a
     * new pair instead.
     *
     * @param string $refreshToken Token from an issue or a previous exchange.
     *
     * @return array{token:string, refresh_token:string} The new pair.
     *
     * @throws RuntimeException 401 — token unknown, expired or already used.
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
     * Revokes one token by its jti (DELETE /tokens/{jti}).
     *
     * Idempotent: revoking an unknown jti is success too — the desired state
     * holds either way.
     *
     * @param string $jti Token id from the jti claim.
     *
     * @throws RuntimeException 500 — store unreachable, the token is NOT
     *                          revoked; retry.
     */
    public function revokeToken(string $jti): void
    {
        $response = $this->request('DELETE', "/tokens/{$jti}");

        if ($response['status'] !== 204) {
            throw new RuntimeException("revoke failed: {$response['status']}");
        }
    }

    /**
     * Revokes every active token of a subject.
     *
     * Endpoint DELETE /subjects/{sub}/tokens. The compromise path: tokens
     * cannot be killed one by one because the caller does not know their jti.
     *
     * @param string $sub Subject whose tokens are killed.
     *
     * @return int Number of revoked tokens; expired ones do not count.
     *
     * @throws RuntimeException 500 — store unreachable, nothing was revoked.
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

// Full token lifecycle: issue, refresh, bulk revoke.
$client = JwtServiceClient::fromEnv();

$issued = $client->issueToken('svc-a', ['svc-b'], true, ['role' => 'admin']);
echo 'issued: ', substr($issued['token'], 0, 32), "...\n";

$refreshed = $client->refreshTokens($issued['refresh_token']);
echo 'refreshed: ', substr($refreshed['token'], 0, 32), "...\n";

echo 'revoked: ', $client->revokeSubject('svc-a'), "\n";
