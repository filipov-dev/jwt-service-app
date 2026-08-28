// The k6 load scenario for `POST /tokens/verify` (JWT-34).
//
// The endpoint was not chosen at random: it is the service's only public
// endpoint and the hottest one — it takes the bulk of the traffic, and it is its
// path that JWT-24 (reusing the Redis connection) and JWT-25 (the JWKS cache)
// clear up.
//
// The scenario does not issue tokens: issuing is behind level 3 (TOTP), and
// computing one-time codes inside k6 is awkward. `run.sh` prepares them and puts
// them into `tokens.json` next to the scenario.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter } from 'k6/metrics';

const tokens = JSON.parse(open('./tokens.json'));

const TARGET = __ENV.TARGET_URL || 'http://host.docker.internal:8080';
const PROXY_SECRET = __ENV.PROXY_SECRET || 'dev-proxy-secret';
const PROXY_HEADER = __ENV.PROXY_HEADER || 'X-Proxy-Secret';
const AUDIENCE = __ENV.AUDIENCE || 'load-test';
// The `iss` of a token comes from the `Host` header of the request, so during
// verification it must match the one the token was issued with, or an honest 401
// follows.
const HOST_HEADER = __ENV.HOST_HEADER || 'jwt-load.local';
// The pause between iterations. It is needed for a before/after comparison at
// the SAME rate: if an optimisation raised the ceiling, then without a limit the
// run moves to a different load level and the latencies become incomparable.
const SLEEP_MS = Number(__ENV.SLEEP_MS || 0);

// Failures are counted by a separate counter: on its own k6 counts only
// transport errors as failed, while we also need 401/429 — they mean the
// measurement is invalid (expired tokens, or a rate limit that was not turned
// off).
const rejected = new Counter('verify_rejected');

export const options = {
    vus: Number(__ENV.VUS || 50),
    duration: __ENV.DURATION || '30s',
    // A threshold on the share of successful responses only. Latency thresholds
    // are deliberately not set for the baseline: a baseline is a measurement, not
    // a check.
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

    if (SLEEP_MS > 0) {
        sleep(SLEEP_MS / 1000);
    }
}
