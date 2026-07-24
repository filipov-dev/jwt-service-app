# Клиентские примеры уровня 3 (TOTP)

Минимально рабочие примеры подключения клиента к эндпоинтам **уровня 3**
(`POST /tokens`, `DELETE /tokens/{jti}`), защищённым TOTP (RFC 6238).

Каждый пример делает одно и то же:

1. читает общий секрет из переменной окружения `AUTH_TOTP_SECRET` (секреты **не**
   зашиты в код);
2. вычисляет текущий TOTP-код по дефолтным параметрам сервиса — **SHA-1, 6 знаков,
   шаг 30 секунд**;
3. вызывает защищённую ручку, передавая код в заголовке **`X-TOTP-Code`**.

> Параметры (алгоритм, число знаков, шаг, имя заголовка) настраиваются на сервере
> через env — см. таблицу в [AGENTS.md](../../AGENTS.md#переменные-окружения). Если
> вы меняли дефолты, синхронизируйте их в клиенте.

## Формат секрета

Секрет по соглашению кодируется в **base32** (совместимо с Google Authenticator и
большинством TOTP-библиотек). Часть низкоуровневых примеров (C, C++, Objective-C,
Erlang, Julia, Lua, PowerShell, F#, VB.NET, Haskell, Zig) для краткости трактуют
`AUTH_TOTP_SECRET` как сырые байты — для них добавьте декодер base32 или храните
секрет в подходящей для примера форме. В комментарии каждого такого файла это
отмечено.

## Индекс языков

| Язык | Файл | Библиотека / приём |
|------|------|--------------------|
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

## Переменные окружения примеров

| Переменная | Назначение |
|-----------|-----------|
| `AUTH_TOTP_SECRET` | Общий TOTP-секрет (base32). |
| `JWT_SERVICE_URL` | Базовый URL сервиса (по умолчанию `http://localhost:8080`). |
