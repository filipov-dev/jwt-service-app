#' jwt-service-app level 3 (TOTP) client: issue, refresh, revoke
#'
#' Install: \code{install.packages(c("otp", "httr", "jsonlite"))}.
#'
#' Env: \code{AUTH_TOTP_SECRET} (base32), \code{JWT_SERVICE_URL} (default
#' \code{http://localhost:8080}).
#'
#' See README.md for endpoints, error codes and client rules.
#'
#' @name jwt-service-client
NULL

library(httr)
library(jsonlite)
library(otp)

#' Host header value
#'
#' Sent as the Host header, becomes the iss claim.
ISSUER_HOST <- "example.com"

#' Service base URL
#'
#' @return URL from the environment, or the default.
service_url <- function() {
  Sys.getenv("JWT_SERVICE_URL", "http://localhost:8080")
}

#' Fresh TOTP code
#'
#' SHA-1, 6 digits, 30-second step.
#'
#' @return Six decimal digits.
totp_code <- function() {
  TOTP$new(Sys.getenv("AUTH_TOTP_SECRET"))$now()
}

#' Send a level 3 request
#'
#' The code is computed right before the call.
#'
#' @param method httr function: \code{POST} or \code{DELETE}.
#' @param path Endpoint path.
#' @param body Request body list, or \code{NULL}.
#' @return httr response object.
do_request <- function(method, path, body = NULL) {
  headers <- add_headers("X-TOTP-Code" = totp_code(), "Host" = ISSUER_HOST)

  if (is.null(body)) {
    method(paste0(service_url(), path), headers)
  } else {
    method(paste0(service_url(), path), headers, body = body, encode = "json")
  }
}

#' POST /tokens
#'
#' @param sub Subject.
#' @param aud Audience vector.
#' @param with_refresh Also ask for a refresh token.
#' @param claims Named list of custom claims.
#' @return List with \code{token} and, if requested, \code{refresh_token}.
#' @examples
#' \dontrun{
#' issued <- issue_token("svc-a", c("svc-b"), with_refresh = TRUE,
#'                       claims = list(role = "admin"))
#' }
issue_token <- function(sub, aud, with_refresh = FALSE, claims = NULL) {
  body <- list(sub = sub, aud = aud, refresh = with_refresh)
  if (!is.null(claims) && length(claims) > 0) body$claims <- claims

  response <- do_request(POST, "/tokens", body)

  if (status_code(response) != 200) {
    stop(sprintf("issue failed: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))
}

#' POST /tokens/refresh
#'
#' Returns a new pair; the old refresh token is dead once the call succeeds.
#'
#' @param refresh_token Token from an issue or a previous refresh.
#' @return List with the new \code{token} and \code{refresh_token}.
refresh_tokens <- function(refresh_token) {
  response <- do_request(POST, "/tokens/refresh", list(refresh_token = refresh_token))

  if (status_code(response) != 200) {
    stop(sprintf("refresh failed: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))
}

#' DELETE /tokens/{jti}
#'
#' Idempotent.
#'
#' @param jti Token id from the \code{jti} claim.
#' @return \code{invisible(NULL)}.
revoke_token <- function(jti) {
  response <- do_request(DELETE, paste0("/tokens/", jti))

  if (status_code(response) != 204) {
    stop(sprintf("revoke failed: %d", status_code(response)))
  }

  invisible(NULL)
}

#' DELETE /subjects/{sub}/tokens
#'
#' @param sub Subject whose tokens are revoked.
#' @return Number of revoked tokens.
revoke_subject <- function(sub) {
  response <- do_request(DELETE, paste0("/subjects/", sub, "/tokens"))

  if (status_code(response) != 200) {
    stop(sprintf("bulk revoke failed: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))$revoked
}

# Issue -> refresh -> revoke.
issued <- issue_token("svc-a", c("svc-b"), with_refresh = TRUE, claims = list(role = "admin"))
cat("issued:", substr(issued$token, 1, 32), "...\n")

refreshed <- refresh_tokens(issued$refresh_token)
cat("refreshed:", substr(refreshed$token, 1, 32), "...\n")

cat("revoked:", revoke_subject("svc-a"), "\n")
