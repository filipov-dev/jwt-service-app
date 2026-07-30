#' Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP)
#'
#' Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
#' токена и массовый отзыв токенов субъекта.
#'
#' Зависимости: \code{install.packages(c("otp", "httr", "jsonlite"))}.
#'
#' Окружение:
#' \itemize{
#'   \item \code{AUTH_TOTP_SECRET} — общий TOTP-секрет в base32 (обязательно);
#'   \item \code{JWT_SERVICE_URL} — базовый URL, по умолчанию \code{http://localhost:8080}.
#' }
#'
#' @section Один код — один запрос:
#' Код считается \strong{заново перед каждым запросом}. При включённой на сервере
#' защите от переигрывания (\code{AUTH_TOTP_REPLAY_PROTECTION}) повторное
#' предъявление того же кода вернёт 401, хотя сам код ещё не истёк.
#'
#' @name jwt-service-client
NULL

library(httr)
library(jsonlite)
library(otp)

#' Значение claim iss
#'
#' Должно совпадать при выпуске и проверке токена.
ISSUER_HOST <- "example.com"

#' Базовый URL сервиса
#'
#' @return Строка с URL из окружения либо значение по умолчанию.
service_url <- function() {
  Sys.getenv("JWT_SERVICE_URL", "http://localhost:8080")
}

#' Вычислить TOTP-код на текущий момент
#'
#' Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
#'
#' @return Строка из шести десятичных знаков.
totp_code <- function() {
  TOTP$new(Sys.getenv("AUTH_TOTP_SECRET"))$now()
}

#' Выполнить запрос к ручке уровня 3
#'
#' Подставляет свежий TOTP-код: один код — один запрос.
#'
#' @param method Функция httr: \code{POST} или \code{DELETE}.
#' @param path Путь ручки, начиная со слеша.
#' @param body Список с телом запроса либо \code{NULL}, если тела нет.
#' @return Объект ответа httr.
do_request <- function(method, path, body = NULL) {
  headers <- add_headers("X-TOTP-Code" = totp_code(), "Host" = ISSUER_HOST)

  if (is.null(body)) {
    method(paste0(service_url(), path), headers)
  } else {
    method(paste0(service_url(), path), headers, body = body, encode = "json")
  }
}

#' Выпустить access-токен
#'
#' Ручка \code{POST /tokens}.
#'
#' @param sub Субъект, которому выдаётся токен (claim \code{sub}).
#' @param aud Вектор получателей (claim \code{aud}); не должен быть пустым.
#' @param with_refresh Запросить refresh-токен для продления сессии.
#' @return Список с полями \code{token} и, если запрашивался, \code{refresh_token}.
#' @examples
#' \dontrun{
#' issued <- issue_token("svc-a", c("svc-b"), with_refresh = TRUE)
#' }
issue_token <- function(sub, aud, with_refresh = FALSE) {
  response <- do_request(POST, "/tokens", list(sub = sub, aud = aud, refresh = with_refresh))

  if (status_code(response) != 200) {
    stop(sprintf("выпуск не удался: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))
}

#' Обменять refresh-токен на новую пару
#'
#' Ручка \code{POST /tokens/refresh}. Старый токен после обмена недействителен:
#' сохраните новый и выбросьте предыдущий.
#'
#' @section Внимание:
#' Не повторяйте обмен старым токеном при потере ответа. Повторное предъявление
#' трактуется как кража и гасит всю семью — и refresh-токены, и выданные по ним
#' access-токены. Надёжнее выпустить пару заново.
#'
#' @param refresh_token Токен из выпуска или прошлого обмена.
#' @return Список с новой парой \code{token} и \code{refresh_token}.
refresh_tokens <- function(refresh_token) {
  response <- do_request(POST, "/tokens/refresh", list(refresh_token = refresh_token))

  if (status_code(response) != 200) {
    stop(sprintf("обмен не удался: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))
}

#' Отозвать один токен
#'
#' Ручка \code{DELETE /tokens/{jti}}. Идемпотентно: отзыв несуществующего
#' \code{jti} — тоже успех.
#'
#' @param jti Идентификатор токена из claim \code{jti}.
#' @return \code{invisible(NULL)}.
revoke_token <- function(jti) {
  response <- do_request(DELETE, paste0("/tokens/", jti))

  if (status_code(response) != 204) {
    stop(sprintf("отзыв не удался: %d — хранилище недоступно, повторите", status_code(response)))
  }

  invisible(NULL)
}

#' Отозвать все токены субъекта
#'
#' Ручка \code{DELETE /subjects/{sub}/tokens}. Нужна при компрометации: гасить
#' токены по одному нельзя, их \code{jti} вызывающему неизвестны.
#'
#' @param sub Субъект, чьи токены гасятся.
#' @return Число отозванных токенов; истёкшие не считаются.
revoke_subject <- function(sub) {
  response <- do_request(DELETE, paste0("/subjects/", sub, "/tokens"))

  if (status_code(response) != 200) {
    stop(sprintf("массовый отзыв не удался: %d", status_code(response)))
  }

  fromJSON(content(response, "text", encoding = "UTF-8"))$revoked
}

# Демонстрация полного жизненного цикла токена.
issued <- issue_token("svc-a", c("svc-b"), with_refresh = TRUE)
cat("выпущен:", substr(issued$token, 1, 32), "...\n")

refreshed <- refresh_tokens(issued$refresh_token)
cat("обновлён:", substr(refreshed$token, 1, 32), "...\n")

cat("отозвано токенов:", revoke_subject("svc-a"), "\n")
