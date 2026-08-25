#' jwt-service-app level 3 (TOTP) client: issue, refresh, revoke
#'
#' Install: \code{install.packages(c("otp", "httr", "jsonlite"))}.
#'
#' Environment:
#' \itemize{
#'   \item \code{AUTH_TOTP_SECRET} — shared TOTP secret, base32 (required);
#'   \item \code{JWT_SERVICE_URL} — base URL, default \code{http://localhost:8080}.
#' }
#'
#' @section One code, one request:
#' The code is recomputed \strong{before every request}. With replay protection
#' on (\code{AUTH_TOTP_REPLAY_PROTECTION}) the server rejects a code it has
#' already seen with 401, even while that code is still inside its time window.
#'
#' @name jwt-service-client
NULL

library(httr)
library(jsonlite)
library(otp)

#' Host header value
#'
#' Sent as the Host header and becomes the iss claim. Must be the same on issue
#' and on verify, or the token will not verify.
ISSUER_HOST <- "example.com"

#' Service base URL
#'
#' @return URL from the environment, or the default.
service_url <- function() {
  Sys.getenv("JWT_SERVICE_URL", "http://localhost:8080")
}

#' Compute a fresh TOTP code for right now
#'
#' Service defaults: SHA-1, 6 digits, 30-second step.
#'
#' @return Six decimal digits.
totp_code <- function() {
  TOTP$new(Sys.getenv("AUTH_TOTP_SECRET"))$now()
}

#' Send a level 3 request
#'
#' The code is computed here rather than reused: one code, one request.
#'
#' @param method httr function: \code{POST} or \code{DELETE}.
#' @param path Endpoint path.
#' @param body Request body list, or \code{NULL} when there is none.
#' @return httr response object.
do_request <- function(method, path, body = NULL) {
  headers <- add_headers("X-TOTP-Code" = totp_code(), "Host" = ISSUER_HOST)

  if (is.null(body)) {
    method(paste0(service_url(), path), headers)
  } else {
    method(paste0(service_url(), path), headers, body = body, encode = "json")
  }
}

#' Issue an access token
#'
#' Endpoint \code{POST /tokens}.
#'
#' @param sub Subject the token is issued to (claim \code{sub}).
#' @param aud Audience vector (claim \code{aud}); must not be empty.
#' @param with_refresh Also return a refresh token for extending the session.
#' @param claims Named list of custom claims (role, scope, tenant): they sit
#'   next to the registered ones, so the consumer reads \code{role}, not
#'   \code{extra.role}. Reserved names (\code{iss}, \code{sub}, \code{aud},
#'   \code{exp}, \code{iat}, \code{nbf}, \code{jti}) give 422 — change lifetime
#'   through \code{ttl}, not \code{exp}.
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

#' Exchange a refresh token for a new pair
#'
#' Endpoint \code{POST /tokens/refresh}. The old token dies on exchange: store
#' the new one and drop the previous.
#'
#' @section Never retry the exchange:
#' When the reply is lost, do not repeat the exchange with the old token. A
#' second presentation reads as theft, and the server revokes the whole family —
#' refresh tokens and the access tokens issued from them. Issue a new pair
#' instead.
#'
#' @param refresh_token Token from an issue or a previous exchange.
#' @return List with the new \code{token} and \code{refresh_token}.
refresh_tokens <- function(refresh_token) {
  response <- do_request(POST, "/tokens/refresh", list(refresh_token = refresh_token))

  if (status_code(response) != 200) {
    stop(sprintf("refresh failed: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))
}

#' Revoke one token
#'
#' Endpoint \code{DELETE /tokens/{jti}}. Idempotent: revoking an unknown
#' \code{jti} is success too.
#'
#' @param jti Token id from the \code{jti} claim.
#' @return \code{invisible(NULL)}.
revoke_token <- function(jti) {
  response <- do_request(DELETE, paste0("/tokens/", jti))

  if (status_code(response) != 204) {
    stop(sprintf("revoke failed: %d — store unreachable, token NOT revoked, retry",
                 status_code(response)))
  }

  invisible(NULL)
}

#' Revoke every token of a subject
#'
#' Endpoint \code{DELETE /subjects/{sub}/tokens}. The compromise path: tokens
#' cannot be killed one by one because the caller does not know their
#' \code{jti}.
#'
#' @param sub Subject whose tokens are killed.
#' @return Number of revoked tokens; expired ones do not count.
revoke_subject <- function(sub) {
  response <- do_request(DELETE, paste0("/subjects/", sub, "/tokens"))

  if (status_code(response) != 200) {
    stop(sprintf("bulk revoke failed: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))$revoked
}

# Full token lifecycle: issue, refresh, bulk revoke.
issued <- issue_token("svc-a", c("svc-b"), with_refresh = TRUE, claims = list(role = "admin"))
cat("issued:", substr(issued$token, 1, 32), "...\n")

refreshed <- refresh_tokens(issued$refresh_token)
cat("refreshed:", substr(refreshed$token, 1, 32), "...\n")

cat("revoked:", revoke_subject("svc-a"), "\n")
