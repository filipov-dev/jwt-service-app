/**
 * @file jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
 *
 * Install: `npm i otplib` (Node 18+ ships `fetch`).
 *
 * Env:
 * - `AUTH_TOTP_SECRET` — shared TOTP secret, base32 (required);
 * - `JWT_SERVICE_URL` — service base URL, default `http://localhost:8080`.
 *
 * The code is recomputed before every request. With replay protection on
 * (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already seen
 * with `401`, even while that code is still inside its time window.
 */

import { authenticator } from 'otplib';

const SECRET = process.env.AUTH_TOTP_SECRET;
const SERVICE = process.env.JWT_SERVICE_URL ?? 'http://localhost:8080';

/**
 * Sent as the Host header and becomes the `iss` claim. Must be the same on
 * issue and on verify, or the token will not verify.
 * @type {string}
 */
const ISSUER_HOST = 'example.com';

/**
 * Fresh code for right now: SHA-1, 6 digits, 30-second step.
 *
 * @returns {string} Six decimal digits.
 */
function totpCode() {
  return authenticator.generate(SECRET);
}

/**
 * Headers with a code computed here, not reused: one code, one request.
 *
 * @returns {Record<string, string>} Headers with a fresh code and `Host`.
 */
function authHeaders() {
  return {
    'X-TOTP-Code': totpCode(),
    Host: ISSUER_HOST,
    'Content-Type': 'application/json',
  };
}

/**
 * Issue an access token (`POST /tokens`).
 *
 * @param {string} sub Subject the token is issued to (`sub` claim).
 * @param {string[]} aud Audience (`aud` claim); must not be empty.
 * @param {boolean} [withRefresh=false] Also return a refresh token for
 *   extending the session.
 * @param {Object<string, *>} [claims={}] Custom claims (role, scope, tenant).
 *   They sit next to the registered ones, so the consumer reads `role`, not
 *   `extra.role`. Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
 *   `jti`) are rejected with `422` — change lifetime through `ttl`, not `exp`.
 *   Count and size are capped server-side.
 * @returns {Promise<{token: string, refresh_token?: string}>} The issued token;
 *   `refresh_token` only if it was requested.
 * @throws {Error} 401 bad code, 422 bad parameters or forbidden claim,
 *   500 JWKS or Redis unavailable.
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
 * Exchange a refresh token for a new pair (`POST /tokens/refresh`).
 *
 * The old token dies on exchange: store the new one and drop the previous.
 *
 * Never retry an exchange with the old token when the reply is lost. A second
 * presentation reads as theft, and the server revokes the whole family —
 * refresh tokens and the access tokens issued from them. Issue a new pair
 * instead.
 *
 * @param {string} refreshToken Token from an issue or a previous exchange.
 * @returns {Promise<{token: string, refresh_token: string}>} The new pair.
 * @throws {Error} 401 — token unknown, expired or already used.
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
 * Revoke one token by its `jti` (`DELETE /tokens/{jti}`).
 *
 * Idempotent: revoking an unknown `jti` is success too — the desired state
 * holds either way.
 *
 * @param {string} jti Token id from the `jti` claim.
 * @returns {Promise<void>}
 * @throws {Error} 500 — store unreachable, the token is NOT revoked; retry.
 */
export async function revokeToken(jti) {
  const response = await fetch(`${SERVICE}/tokens/${jti}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (!response.ok) throw new Error(`revoke failed: ${response.status}`);
}

/**
 * Revoke every active token of a subject (`DELETE /subjects/{sub}/tokens`).
 *
 * The compromise path: tokens cannot be killed one by one because the caller
 * does not know their `jti`.
 *
 * @param {string} sub Subject whose tokens are killed.
 * @returns {Promise<number>} Number of revoked tokens; expired ones do not count.
 * @throws {Error} 500 — store unreachable, nothing was revoked.
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

/** Full token lifecycle: issue, refresh, bulk revoke. */
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
