// Нагрузочный сценарий k6 для `POST /tokens/verify` (JWT-34).
//
// Ручка выбрана не случайно: это единственная публичная ручка сервиса и самая
// горячая — на неё приходится основной трафик, и именно её путь расчищают
// JWT-24 (переиспользование соединения Redis) и JWT-25 (кеш JWKS).
//
// Токены сценарий не выпускает: выпуск закрыт уровнем 3 (TOTP), а считать
// одноразовые коды внутри k6 неудобно. Их готовит `run.sh` и кладёт в
// `tokens.json` рядом со сценарием.

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const tokens = JSON.parse(open('./tokens.json'));

const TARGET = __ENV.TARGET_URL || 'http://host.docker.internal:8080';
const PROXY_SECRET = __ENV.PROXY_SECRET || 'dev-proxy-secret';
const PROXY_HEADER = __ENV.PROXY_HEADER || 'X-Proxy-Secret';
const AUDIENCE = __ENV.AUDIENCE || 'load-test';
// `iss` токена берётся из заголовка `Host` запроса, поэтому при проверке он
// обязан совпадать с тем, с которым токен выпускали, иначе будет честный 401.
const HOST_HEADER = __ENV.HOST_HEADER || 'jwt-load.local';

// Отказы считаем отдельным счётчиком: k6 сам по себе считает failed только
// транспортные ошибки, а нам нужны и 401/429 — они означают, что замер
// невалиден (протухшие токены либо не отключённый rate limit).
const rejected = new Counter('verify_rejected');

export const options = {
    vus: Number(__ENV.VUS || 50),
    duration: __ENV.DURATION || '30s',
    // Порог только на долю успешных ответов. Пороги на латентность для baseline
    // намеренно не ставим: baseline — это измерение, а не проверка.
    thresholds: {
        checks: ['rate>0.99'],
    },
    summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

export default function () {
    const token = tokens[Math.floor(Math.random() * tokens.length)];

    const res = http.post(
        `${TARGET}/tokens/verify`,
        JSON.stringify({ token: token, audience: AUDIENCE }),
        {
            headers: {
                'Content-Type': 'application/json',
                [PROXY_HEADER]: PROXY_SECRET,
                Host: HOST_HEADER,
            },
            tags: { name: 'verify' },
        },
    );

    const ok = check(res, { 'status 200': (r) => r.status === 200 });
    if (!ok) {
        rejected.add(1, { status: String(res.status) });
    }
}
