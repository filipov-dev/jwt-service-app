# Cloudflare — level 2 (the proxy secret)

## Option A — Transform Rules (Modify Request Header)
Create a "Modify Request Header" rule with TWO actions, in this order:

1. **Remove** the `X-Proxy-Secret` header — this drops the client-supplied
   version.
2. **Set static** header `X-Proxy-Secret` = the secret value.

The secret value is stored in the Dashboard as it is; for a secret the Workers
option below is preferable (Transform Rules do not read the Secrets Store).

## Option B — Cloudflare Workers (the secret from a Secret binding)
The secret goes into a Worker Secret (`wrangler secret put PROXY_SECRET`) and
never reaches the code:

```js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = new Headers(request.headers);
    // (1) Delete the client-supplied version of the header.
    headers.delete("X-Proxy-Secret");
    // (2) Set the secret from the Secret binding.
    headers.set("X-Proxy-Secret", env.PROXY_SECRET);
    return fetch("http://jwt_service:8080" + url.pathname + url.search, {
      method: request.method, headers, body: request.body,
    });
  },
};
```
