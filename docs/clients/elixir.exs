# Elixir — библиотека: nimble_totp (`{:nimble_totp, "~> 1.0"}`, :req для HTTP)
secret = System.fetch_env!("AUTH_TOTP_SECRET") |> Base.decode32!(padding: false)
service = System.get_env("JWT_SERVICE_URL", "http://localhost:8080")

code = NimbleTOTP.verification_code(secret)          # SHA-1, 6, 30с

{:ok, resp} =
  Req.post(service <> "/tokens",
    headers: [{"x-totp-code", code}, {"host", "example.com"}],
    json: %{sub: "svc-a", aud: ["svc-b"]}
  )

IO.puts("#{resp.status}")
