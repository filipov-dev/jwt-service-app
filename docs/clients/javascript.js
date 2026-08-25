/**
 * @file jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Install: `npm i otplib` (Node 18+ ships `fetch`).
 * Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
 * `http://localhost:8080`).
 * See README.md for endpoints, error codes and client rules.
 */

import { authenticator } from 'otplib';

const SECRET = process.env.AUTH_TOTP_SECRET;
const SERVICE = process.env.JWT_SERVICE_URL ?? 'http://localhost:8080';

/**
 * Sent as the Host header, becomes the `iss` claim.
 * @type {string}
 */
const ISSUER_HOST = 'example.com';

/**
 * Fresh TOTP code: SHA-1, 6 digits, 30-second step.
 * @returns {string}
 */
function totpCode() {
  return authenticator.generate(SECRET);
}

/**
 * Headers with a code computed right before the call.
 * @returns {Record<string, string>}
 */
function authHeaders() {
  return {
    'X-TOTP-Code': totpCode(),
    Host: ISSUER_HOST,
    'Content-Type': 'application/json',
  };
}

/**
 * `POST /tokens`
 *
 * @param {string} sub
 * @param {string[]} aud
 * @param {boolean} [withRefresh=false]
 * @param {Object<string, *>} [claims={}]
 * @returns {Promise<{token: string, refresh_token?: string}>}
 */
export async function issueToken(sub, aud, withRefresh = false, claims = {}) {
  const body = { sub, aud, refresh: withRefresh };
  if (Object.keys(claims).length > 0) body.claims = claims;

  const response = await fetch(`${SERVICE}/tokens`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
  });

  if (!response.ok) throw new Error(`issue failed: ${response.status}`);
  return response.json();
}

/**
 * `POST /tokens/refresh` — returns a new pair; the old refresh token is dead.
 *
 * @param {string} refreshToken
 * @returns {Promise<{token: string, refresh_token: string}>}
 */
export async function refreshTokens(refreshToken) {
  const response = await fetch(`${SERVICE}/tokens/refresh`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) throw new Error(`refresh failed: ${response.status}`);
  return response.json();
}

/**
 * `DELETE /tokens/{jti}` — idempotent.
 *
 * @param {string} jti
 * @returns {Promise<void>}
 */
export async function revokeToken(jti) {
  const response = await fetch(`${SERVICE}/tokens/${jti}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (!response.ok) throw new Error(`revoke failed: ${response.status}`);
}

/**
 * `DELETE /subjects/{sub}/tokens`
 *
 * @param {string} sub
 * @returns {Promise<number>} Number of revoked tokens.
 */
export async function revokeSubject(sub) {
  const response = await fetch(`${SERVICE}/subjects/${sub}/tokens`, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (!response.ok) throw new Error(`bulk revoke failed: ${response.status}`);
  const body = await response.json();
  return body.revoked;
}

/** Issue -> refresh -> revoke. */
async function main() {
  const issued = await issueToken('svc-a', ['svc-b'], true, { role: 'admin' });
  console.log('issued:', issued.token.slice(0, 32), '...');

  const refreshed = await refreshTokens(issued.refresh_token);
  console.log('refreshed:', refreshed.token.slice(0, 32), '...');

  console.log('revoked:', await revokeSubject('svc-a'));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
