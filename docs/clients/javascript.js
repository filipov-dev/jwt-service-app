// JavaScript (Node.js) — библиотека: otplib (`npm i otplib`)
import { authenticator } from 'otplib';

const secret = process.env.AUTH_TOTP_SECRET;               // base32
const service = process.env.JWT_SERVICE_URL ?? 'http://localhost:8080';

const code = authenticator.generate(secret);               // SHA-1, 6 знаков, 30с

const resp = await fetch(`${service}/tokens`, {
  method: 'POST',
  headers: { 'X-TOTP-Code': code, 'Host': 'example.com', 'Content-Type': 'application/json' },
  body: JSON.stringify({ sub: 'svc-a', aud: ['svc-b'] }),
});
console.log(resp.status, await resp.text());
