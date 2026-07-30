"""Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).

Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
токена и массовый отзыв токенов субъекта.

Зависимости::

    pip install pyotp requests

Окружение:
    AUTH_TOTP_SECRET: общий TOTP-секрет в base32 (обязательно).
    JWT_SERVICE_URL: базовый URL сервиса, по умолчанию http://localhost:8080.

.. important::
   Код считается **заново перед каждым запросом**. При включённой на сервере
   защите от переигрывания (``AUTH_TOTP_REPLAY_PROTECTION``) повторное
   предъявление того же кода вернёт 401, хотя сам код ещё не истёк.
"""

import os

import pyotp
import requests

SECRET = os.environ["AUTH_TOTP_SECRET"]
SERVICE = os.environ.get("JWT_SERVICE_URL", "http://localhost:8080")

#: Значение claim ``iss``. Должно совпадать при выпуске и проверке токена.
ISSUER_HOST = "example.com"


def totp_code() -> str:
    """Вычисляет TOTP-код на текущий момент.

    Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.

    :return: Код из шести десятичных знаков.
    """
    return pyotp.TOTP(SECRET).now()


def auth_headers() -> dict:
    """Собирает заголовки для запроса к ручке уровня 3.

    :return: Заголовки со свежим TOTP-кодом и ``Host``.
    """
    return {"X-TOTP-Code": totp_code(), "Host": ISSUER_HOST}


def issue_token(
    sub: str,
    aud: list,
    with_refresh: bool = False,
    claims: dict = None,
) -> dict:
    """Выпускает access-токен (``POST /tokens``).

    :param sub: Субъект, которому выдаётся токен (claim ``sub``).
    :param aud: Список получателей (claim ``aud``); не должен быть пустым.
    :param with_refresh: Запросить вместе с токеном refresh для продления сессии.
    :param claims: Произвольные claims (роли, scope, tenant), попадают в payload
        рядом с зарегистрированными. Служебные имена (``iss``, ``sub``, ``aud``,
        ``exp``, ``iat``, ``nbf``, ``jti``) переопределять нельзя — будет 422.
        Число ключей и объём ограничены на сервере.
    :return: ``{"token": ..., "refresh_token": ...}``; ``refresh_token``
        присутствует, только если он запрашивался.
    :raises requests.HTTPError: 401 — неверный TOTP-код, 422 — некорректные
        параметры или запрещённый claim, 500 — недоступны JWKS или Redis.
    """
    payload = {"sub": sub, "aud": aud, "refresh": with_refresh}
    if claims:
        payload["claims"] = claims

    response = requests.post(f"{SERVICE}/tokens", headers=auth_headers(), json=payload)
    response.raise_for_status()
    return response.json()


def refresh_tokens(refresh_token: str) -> dict:
    """Обменивает refresh-токен на новую пару (``POST /tokens/refresh``).

    Старый токен после обмена недействителен: сохраните новый и выбросьте
    предыдущий.

    .. warning::
       Не повторяйте обмен старым токеном при потере ответа. Повторное
       предъявление трактуется как кража и гасит **всю семью** — и refresh, и
       выданные по ним access-токены. Надёжнее выпустить пару заново.

    :param refresh_token: Токен, полученный при выпуске или прошлом обмене.
    :return: ``{"token": ..., "refresh_token": ...}`` — новая пара.
    :raises requests.HTTPError: 401 — токен неизвестен, истёк или уже
        использован.
    """
    response = requests.post(
        f"{SERVICE}/tokens/refresh",
        headers=auth_headers(),
        json={"refresh_token": refresh_token},
    )
    response.raise_for_status()
    return response.json()


def revoke_token(jti: str) -> None:
    """Отзывает один токен по его ``jti`` (``DELETE /tokens/{jti}``).

    Идемпотентно: отзыв несуществующего ``jti`` — тоже успех, желаемое состояние
    достигнуто.

    :param jti: Идентификатор токена из claim ``jti``.
    :raises requests.HTTPError: 500 — хранилище недоступно, отзыв **не выполнен**
        (повторите попытку).
    """
    response = requests.delete(f"{SERVICE}/tokens/{jti}", headers=auth_headers())
    response.raise_for_status()


def revoke_subject(sub: str) -> int:
    """Отзывает все активные токены субъекта.

    Ручка ``DELETE /subjects/{sub}/tokens``. Нужна при компрометации: гасить
    токены по одному нельзя, их ``jti`` вызывающему неизвестны.

    :param sub: Субъект, чьи токены гасятся.
    :return: Число отозванных токенов; уже истёкшие не считаются.
    :raises requests.HTTPError: 500 — хранилище недоступно, отзыв не выполнен.
    """
    response = requests.delete(f"{SERVICE}/subjects/{sub}/tokens", headers=auth_headers())
    response.raise_for_status()
    return response.json()["revoked"]


def main() -> None:
    """Демонстрирует полный жизненный цикл токена."""
    issued = issue_token("svc-a", ["svc-b"], with_refresh=True, claims={"role": "admin"})
    print("выпущен:", issued["token"][:32], "...")

    refreshed = refresh_tokens(issued["refresh_token"])
    print("обновлён:", refreshed["token"][:32], "...")

    revoked = revoke_subject("svc-a")
    print("отозвано токенов:", revoked)


if __name__ == "__main__":
    main()
