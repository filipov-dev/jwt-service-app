# Client examples for level 3 (TOTP)

Working examples of connecting a client to **every level 3 endpoint**, protected
by TOTP (RFC 6238).

Every example:

1. reads the shared secret from the `AUTH_TOTP_SECRET` environment variable
   (secrets are **not** baked into the code);
2. computes the TOTP code with the service's default parameters — **SHA-1, 6
   digits, a 30-second step** — **anew before every request**;
3. calls the endpoint, passing the code in the **`X-TOTP-Code`** header;
4. shows the full scenario: issue a pair → exchange the refresh token → revoke.

> The parameters (algorithm, number of digits, step, header name) are configured
> on the server through env — see the table in
> [AGENTS.md](../../AGENTS.md#configuration-environment-variables). If you changed
> the defaults, mirror them in the client.

## The level 3 endpoints

| Endpoint | Purpose | Request body | Successful response |
|----------|---------|--------------|---------------------|
| `POST /tokens` | Issue a token | `{"sub", "aud", "ttl"?, "refresh"?, "claims"?}` | `200` plus `{"token", "refresh_token"?}` |
| `POST /tokens/refresh` | Exchange a refresh token | `{"refresh_token"}` | `200` plus `{"token", "refresh_token"}` |
| `DELETE /tokens/{jti}` | Revoke one token | — | `204` |
| `DELETE /subjects/{sub}/tokens` | Revoke every token of a subject | — | `200` plus `{"revoked": N}` |

Token verification (`POST /tokens/verify`) is level 2 rather than TOTP: it is
called by the reverse proxy with its own secret, so it is absent from these
examples.

### Response codes

| Code | When | What the client should do |
|------|------|---------------------------|
| `401` | A wrong, expired or already presented TOTP code; on `/tokens/refresh`, an unknown, expired or already used refresh token | Recompute the code and retry; for a refresh token, issue a new pair and do **not** retry the exchange |
| `403` | `Host` is outside the issuer allowlist (issuing and the refresh exchange) | Agree the `Host` value with the service administrator |
| `422` | Invalid parameters or a forbidden claim name | Fix the request body; change the lifetime through `ttl`, not through `exp` |
| `500` | The JWKS or Redis is unavailable | The operation was **not** performed — retry |

Revocation (`DELETE /tokens/{jti}`) is idempotent: revoking a `jti` that does not
exist is also `204`, because the desired state has been reached. Bulk revocation
returns the number of tokens killed; already expired ones do not count.

### The `Host` header determines `iss`

The value of the `iss` claim comes from the `Host` header of the request. It must
**match** at issue time and at verification time, or the token fails
verification. In the examples it is set explicitly (`example.com`) — substitute
your own value.

An instance may restrict the list of acceptable issuers
(`TOKEN_ISSUER_ALLOWLIST` on the service side). A `Host` outside the list then
gets `403` on issuing and on a refresh exchange, and `401` on verification —
agree the value with the service administrator.

## Custom claims

The `claims` field in the body of `POST /tokens` adds arbitrary values to the
payload — roles, scope, tenant, an internal identifier:

```json
{"sub": "user1", "aud": ["api1"], "claims": {"role": "admin", "scope": ["read"]}}
```

They sit in the payload **alongside** the registered ones, so the consumer of the
token reads `role`, not `extra.role`.

The limits:

- **reserved names are forbidden** — `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`,
  `jti`; an attempt to override one gives `422`. Change the lifetime through
  `ttl`, not through `exp`;
- **the number of keys and the size are limited** (`TOKEN_CLAIMS_MAX_COUNT`,
  `TOKEN_CLAIMS_MAX_BYTES`): a token travels in headers and a bloated payload
  breaks proxies;
- **claims are not carried over on a refresh exchange** — the service does not
  remember them. Need the same claims in the renewed token? Issue a new pair.

## Refresh tokens: rotation and the theft detector

`"refresh": true` in the body of `POST /tokens` returns a `refresh_token`
alongside the token — an opaque string for extending a session without signing in
again.

The rules a client must follow:

1. **After an exchange the old refresh token is invalid.** Every exchange returns
   a new one — store it and throw the previous one away.
2. **Do not retry an exchange with the old token.** If the response was lost but
   the exchange went through on the server, another attempt with the same refresh
   token is treated as theft.
3. **Presenting one twice kills the whole family.** The server cannot tell a
   thief from the rightful owner, so it revokes the entire chain: the refresh
   tokens and the access tokens issued through them. The client has to sign in
   again.

The practical conclusion: store the new `refresh_token` **before** you consider
the operation successful, and when in doubt issue a new pair rather than retrying
the exchange.

## One code, one request

**Compute the code anew before every request.** Do not cache it and do not reuse
it between calls, even while the window is still open.

The reason: the server may have replay protection enabled
(`AUTH_TOTP_REPLAY_PROTECTION`). It then remembers a presented code for the
duration of the window, and **a second request with the same code gets `401`** —
even though the code itself is still valid.

What breaks in practice:

- **A retry on timeout.** If a request got no response and you repeat it with the
  same code, the repeat is rejected. Recompute the code before retrying.
- **Several operations in a row.** Issuing a token and immediately revoking
  another with one code does not work — every call needs its own.
- **A worker pool with a shared code.** If the code is computed once and handed
  to several concurrent requests, exactly one of them goes through.

The flag is **off** by default, and without it a code is replayable — but write
the client as though it were on: enabling it on the server then breaks nothing.
Every example below follows that rule — the code is computed immediately before
the call.

## The secret format

By convention the secret is encoded in **base32** (compatible with Google
Authenticator and most TOTP libraries). Some of the low-level examples (C, C++,
Objective-C, Erlang, Julia, Lua, PowerShell, F#, VB.NET, Haskell, Zig) treat
`AUTH_TOTP_SECRET` as raw bytes for brevity — for those, add a base32 decoder or
store the secret in the form the example expects. The header of each such file
says so.

## The language index

Every example covers all four endpoints and is **self-contained**: the comments
are English and to the point — they explain what a call does and why it is done
that way (refresh rotation and killing the family, "one code, one request", the
idempotency of revocation, the claim limits, the response codes) — in the
notation the language uses (JSDoc, docstrings, Javadoc, KDoc, rustdoc, PHPDoc,
YARD, Doxygen, POD, edoc, Haddock, roxygen2, LDoc, comment-based help). A file
can be read without opening this README; the same material is gathered here in
one place and is translated together with the site.

| Language | File | Library / technique |
|----------|------|---------------------|
| Python | [python.py](python.py) | `pyotp` |
| JavaScript (Node) | [javascript.js](javascript.js) | `otplib` |
| TypeScript | [typescript.ts](typescript.ts) | `otplib` |
| Java | [Java.java](Java.java) | `java-otp` + `commons-codec` |
| C# | [csharp.cs](csharp.cs) | `Otp.NET` |
| Go | [go.go](go.go) | `pquerna/otp` |
| Rust | [rust.rs](rust.rs) | `totp-rs` + `reqwest` |
| PHP | [php.php](php.php) | `spomky-labs/otphp` |
| Ruby | [ruby.rb](ruby.rb) | `rotp` |
| C | [c.c](c.c) | OpenSSL HMAC + libcurl |
| C++ | [cpp.cpp](cpp.cpp) | OpenSSL HMAC + cpp-httplib |
| Kotlin | [kotlin.kt](kotlin.kt) | `kotlin-onetimepassword` |
| Swift | [swift.swift](swift.swift) | `SwiftOTP` |
| Objective-C | [objc.m](objc.m) | CommonCrypto HMAC |
| Scala | [scala.scala](scala.scala) | `java-otp` + `sttp` |
| Dart | [dart.dart](dart.dart) | `otp` + `http` |
| Elixir | [elixir.exs](elixir.exs) | `nimble_totp` + `req` |
| Erlang | [erlang.erl](erlang.erl) | `crypto` + `httpc` |
| Haskell | [haskell.hs](haskell.hs) | `oath` + `http-conduit` |
| Clojure | [clojure.clj](clojure.clj) | `one-time` + `clj-http` |
| Groovy | [groovy.groovy](groovy.groovy) | `java-otp` (Grab) |
| Perl | [perl.pl](perl.pl) | `Authen::OATH` + `Convert::Base32` |
| Lua | [lua.lua](lua.lua) | `luaossl` + `lua-http` |
| R | [r.R](r.R) | `otp` + `httr` |
| Julia | [julia.jl](julia.jl) | `SHA` + `HTTP` |
| Shell / Bash | [bash.sh](bash.sh) | `oathtool` + `curl` |
| PowerShell | [powershell.ps1](powershell.ps1) | `HMACSHA1` (.NET) |
| F# | [fsharp.fsx](fsharp.fsx) | `HMACSHA1` (.NET) |
| Visual Basic .NET | [vbnet.vb](vbnet.vb) | `HMACSHA1` (.NET) |
| Zig | [zig.zig](zig.zig) | `std.crypto` HMAC-SHA1 |

## The environment variables of the examples

| Variable | Purpose |
|----------|---------|
| `AUTH_TOTP_SECRET` | The shared TOTP secret (base32). |
| `JWT_SERVICE_URL` | The base URL of the service (`http://localhost:8080` by default). |
