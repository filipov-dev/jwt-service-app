# R — библиотека: otp (`install.packages("otp")`) + httr
library(otp)
library(httr)

secret  <- Sys.getenv("AUTH_TOTP_SECRET")                    # base32
service <- Sys.getenv("JWT_SERVICE_URL", "http://localhost:8080")

code <- TOTP$new(secret)$now()                               # SHA-1, 6, 30с

resp <- POST(paste0(service, "/tokens"),
             add_headers(`X-TOTP-Code` = code, Host = "example.com"),
             content_type_json(),
             body = '{"sub":"svc-a","aud":["svc-b"]}')
cat(status_code(resp), "\n")
