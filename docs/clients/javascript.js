/**
 * @file Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
 *
 * Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
 * токена и массовый отзыв токенов субъекта.
 *
 * Зависимости: `npm i otplib` (Node 18+ — `fetch` встроен).
 *
 * Окружение:
 * - `AUTH_TOTP_SECRET` — общий TOTP-секрет в base32 (обязательно);
 * - `JWT_SERVICE_URL` — базовый URL сервиса, по умолчанию `http://localhost:8080`.
 *
 * ВАЖНО: код считается заново перед каждым запросом. При включённой на сервере
 * защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление
 * того же кода вернёт 401, хотя сам код ещё не истёк.
 */

import { authenticator } from 'otplib';

const SECRET = process.env.AUTH_TOTP_SECRET;
const SERVICE = process.env.JWT_SERVICE_URL ?? 'http://localhost:8080';

/**
 * Значение claim `iss`. Должно совпадать при выпуске и проверке токена.
 * @type {string}
 */
const ISSUER_HOST = 'example.com';

/**
 * Вычисляет TOTP-код на текущий момент.
 *
 * Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
 *
 * @returns {string} Код из шести десятичных знаков.
 */
function totpCode() {
  return authenticator.generate(SECRET);
}

/**
 * Собирает заголовки для запроса к ручке уровня 3.
 *
 * @returns {Record<string, string>} Заголовки со свежим TOTP-кодом и `Host`.
 */
function authHeaders() {
  return {
    'X-TOTP-Code': totpCode(),
    Host: ISSUER_HOST,
    'Content-Type': 'application/json',
  };
}

/**
 * Выпускает access-токен (`POST /tokens`).
 *
 * @param {string} sub Субъект, которому выдаётся токен (claim `sub`).
 * @param {string[]} aud Список получателей (claim `aud`); не должен быть пустым.
 * @param {boolean} [withRefresh=false] Запросить вместе с токеном refresh для
 *   продления сессии.
 * @returns {Promise<{token: string, refresh_token?: string}>} Выпущенный токен;
 *   `refresh_token` присутствует, только если запрашивался.
 * @throws {Error} 401 — неверный TOTP-код, 422 — некорректные параметры,
 *   500 — недоступны JWKS или Redis.
 */
export async function issueToken(sub, aud, withRefresh = false) {
  const response = await fetch(`${SERVICE}/tokens`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ sub, aud, refresh: withRefresh }),
  });

  if (!response.ok) throw new Error(`выпуск не удался: ${response.status}`);
  return response.json();
}

/**
 * Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).
 *
 * Старый токен после обмена недействителен: сохраните новый и выбросьте
 * предыдущий.
 *
 * ВНИМАНИЕ: не повторяйте обмен старым токеном при потере ответа. Повторное
 * предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
 * выданные по ним access-токены. Надёжнее выпустить пару заново.
 *
 * @param {string} refreshToken Токен, полученный при выпуске или прошлом обмене.
 * @returns {Promise<{token: string, refresh_token: string}>} Новая пара.
 * @throws {Error} 401 — токен неизвестен, истёк или уже использован.
 */
export async function refreshTokens(refreshToken) {
  const response = await fetch(`${SERVICE}/tokens/refresh`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!response.ok) throw new Error(`обмен не удался: ${response.status}`);
  return response.json();
}

/**
 * Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).
 *
 * Идемпотентно: отзыв несуществующего `jti` — тоже успех, желаемое состояние
 * достигнуто.
 *
 * @param {string} jti Идентификатор токена из claim `jti`.
 * @returns {Promise<void>}
 * @throws {Error} 500 — хранилище недоступно, отзыв НЕ выполнен (повторите).
 */
export async function revokeToken(jti) {
  const response = await fetch(`${SERVICE}/tokens/${jti}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (!response.ok) throw new Error(`отзыв не удался: ${response.status}`);
}

/**
 * Отзывает все активные токены субъекта (`DELETE /subjects/{sub}/tokens`).
 *
 * Нужен при компрометации: гасить токены по одному нельзя, их `jti` вызывающему
 * неизвестны.
 *
 * @param {string} sub Субъект, чьи токены гасятся.
 * @returns {Promise<number>} Число отозванных токенов; истёкшие не считаются.
 * @throws {Error} 500 — хранилище недоступно, отзыв не выполнен.
 */
export async function revokeSubject(sub) {
  const response = await fetch(`${SERVICE}/subjects/${sub}/tokens`, {
    method: 'DELETE',
    headers: authHeaders(),
  });

  if (!response.ok) throw new Error(`массовый отзыв не удался: ${response.status}`);
  const body = await response.json();
  return body.revoked;
}

/** Демонстрирует полный жизненный цикл токена. */
async function main() {
  const issued = await issueToken('svc-a', ['svc-b'], true);
  console.log('выпущен:', issued.token.slice(0, 32), '...');

  const refreshed = await refreshTokens(issued.refresh_token);
  console.log('обновлён:', refreshed.token.slice(0, 32), '...');

  console.log('отозвано токенов:', await revokeSubject('svc-a'));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
