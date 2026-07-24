# Cloudflare — уровень 2 (proxy-secret)

## Вариант A — Transform Rules (Modify Request Header)
Создайте правило "Modify Request Header" с ДВУМЯ действиями по порядку:

1. **Remove** header `X-Proxy-Secret` — убирает клиентскую версию.
2. **Set static** header `X-Proxy-Secret` = значение секрета.

Значение секрета в Dashboard хранится как есть; для секрета предпочтителен
Workers-вариант ниже (Transform Rules не читают Secrets Store).

## Вариант B — Cloudflare Workers (секрет из Secret binding)
Секрет кладётся в Worker Secret (`wrangler secret put PROXY_SECRET`) и никогда не
попадает в код:

```js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = new Headers(request.headers);
    // (1) Удаляем клиентскую версию заголовка.
    headers.delete("X-Proxy-Secret");
    // (2) Ставим секрет из Secret binding.
    headers.set("X-Proxy-Secret", env.PROXY_SECRET);
    return fetch("http://jwt_service:8080" + url.pathname + url.search, {
      method: request.method, headers, body: request.body,
    });
  },
};
```
