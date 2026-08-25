/**
 * @file jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Install: `npm i otplib` (Node 18+ ships `fetch`).
 * Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
 * `http://localhost:8080`).
 * See README.md for endpoints, error codes and client rules.
 */

import { authenticator } from 'otplib';

const SECRET: string = process.env.AUTH_TOTP_SECRET!;
const SERVICE: string = process.env.JWT_SERVICE_URL ?? 'http://localhost:8080';

/** Sent as the Host header, becomes the `iss` claim. */
const ISSUER_HOST = 'example.com';

/** Response of an issue or refresh call. */
export interface TokenResponse {
  /** Signed JWT: `header.payload.signature`. */
  token: string;
  /** Present only when a refresh token was requested. */
  refresh_token?: string;
}

/** Response of a bulk revoke call. */
export interface RevokeGroupResponse {
  /** Number of revoked tokens. */
  revoked: number;
}

/** Fresh TOTP code: SHA-1, 6 digits, 30-second step. */
function totpCode(): string {
  return authenticator.generate(SECRET);
}

/** Headers with a code computed right before the call. */
function authHeaders(): Record<string, string> {
  return {
    'X-TOTP-Code': totpCode(),
    Host: ISSUER_HOST,
    'Content-Type': 'application/json',
  };
}

/** `POST /tokens` */
export async function issueToken(
  sub: string,
  aud: string[],
  withRefresh = false,
  claims: Record<string, unknown> = {},
): Promise<TokenResponse> {
  const body: Record<string, unknown> = { sub, aud, refresh: withRefresh };
  if (Object.keys(claims).length > 0) body.claims = claims;

  const response = await fetch(`${SERVICE}/tokens`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  });

  if (!response.ok) throw new Error(`issue failed: ${response.status}`);
  return (await response.json()) as TokenResponse;
}

/** `POST /tokens/refresh` — returns a new pair; the old refresh token is dead. */
export async function refreshTokens(refreshToken: string): Promise<TokenResponse> {
  const response = await fetch(`${SERVICE}/tokens/refresh`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) throw new Error(`refresh failed: ${response.status}`);
  return (await response.json()) as TokenResponse;
}

/** `DELETE /tokens/{jti}` — idempotent. */
export async function revokeToken(jti: string): Promise<void> {
  const response = await fetch(`${SERVICE}/tokens/${jti}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (!response.ok) throw new Error(`revoke failed: ${response.status}`);
}

/** `DELETE /subjects/{sub}/tokens` — returns the number of revoked tokens. */
export async function revokeSubject(sub: string): Promise<number> {
  const response = await fetch(`${SERVICE}/subjects/${sub}/tokens`, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (!response.ok) throw new Error(`bulk revoke failed: ${response.status}`);
  const body = (await response.json()) as RevokeGroupResponse;
  return body.revoked;
}

/** Issue -> refresh -> revoke. */
async function main(): Promise<void> {
  const issued = await issueToken('svc-a', ['svc-b'], true, { role: 'admin' });
  console.log('issued:', issued.token.slice(0, 32), '...');

  const refreshed = await refreshTokens(issued.refresh_token!);
  console.log('refreshed:', refreshed.token.slice(0, 32), '...');

  console.log('revoked:', await revokeSubject('svc-a'));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
