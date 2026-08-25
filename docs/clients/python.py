"""jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

Install: pip install pyotp requests
Env: AUTH_TOTP_SECRET (base32), JWT_SERVICE_URL (default http://localhost:8080).

The code is recomputed before every request. With replay protection on
(``AUTH_TOTP_REPLAY_PROTECTION``) the server rejects a code it has already seen
with 401, even while that code is still inside its time window.
"""

import os

import pyotp
import requests

SECRET = os.environ["AUTH_TOTP_SECRET"]
SERVICE = os.environ.get("JWT_SERVICE_URL", "http://localhost:8080")

#: Sent as the Host header and becomes the ``iss`` claim. Must be the same on
#: issue and on verify, or the token will not verify.
ISSUER_HOST = "example.com"


def totp_code() -> str:
    """Fresh code for right now: SHA-1, 6 digits, 30-second step.

    :return: Six decimal digits.
    """
    return pyotp.TOTP(SECRET).now()


def auth_headers() -> dict:
    """Headers with a code computed here, not reused: one code, one request.

    :return: Headers with a fresh code and ``Host``.
    """
    return {"X-TOTP-Code": totp_code(), "Host": ISSUER_HOST}


def issue_token(
    sub: str,
    aud: list,
    with_refresh: bool = False,
    claims: dict = None,
) -> dict:
    """Issue an access token (``POST /tokens``).

    :param sub: Subject the token is issued to (``sub`` claim).
    :param aud: Audience (``aud`` claim); must not be empty.
    :param with_refresh: Also return a refresh token for extending the session.
    :param claims: Custom claims (role, scope, tenant). They sit next to the
        registered ones, so the consumer reads ``role``, not ``extra.role``.
        Reserved names (``iss``, ``sub``, ``aud``, ``exp``, ``iat``, ``nbf``,
        ``jti``) are rejected with 422 — change lifetime through ``ttl``, not
        ``exp``. Count and size are capped server-side.
    :return: ``{"token": ..., "refresh_token": ...}``; ``refresh_token`` only if
        it was requested.
    :raises requests.HTTPError: 401 bad code, 422 bad parameters or forbidden
        claim, 500 JWKS or Redis unavailable.
    """
    payload = {"sub": sub, "aud": aud, "refresh": with_refresh}
    if claims:
        payload["claims"] = claims

    response = requests.post(f"{SERVICE}/tokens", headers=auth_headers(), json=payload)
    response.raise_for_status()
    return response.json()


def refresh_tokens(refresh_token: str) -> dict:
    """Exchange a refresh token for a new pair (``POST /tokens/refresh``).

    The old token dies on exchange: store the new one and drop the previous.

    .. warning::
       Never retry an exchange with the old token when the reply is lost. A
       second presentation reads as theft, and the server revokes the whole
       family — refresh tokens and the access tokens issued from them. Issue a
       new pair instead.

    :param refresh_token: Token from an issue or a previous exchange.
    :return: ``{"token": ..., "refresh_token": ...}`` — the new pair.
    :raises requests.HTTPError: 401 — token unknown, expired or already used.
    """
    response = requests.post(
        f"{SERVICE}/tokens/refresh",
        headers=auth_headers(),
        json={"refresh_token": refresh_token},
    )
    response.raise_for_status()
    return response.json()


def revoke_token(jti: str) -> None:
    """Revoke one token by its ``jti`` (``DELETE /tokens/{jti}``).

    Idempotent: revoking an unknown ``jti`` is success too — the desired state
    holds either way.

    :param jti: Token id from the ``jti`` claim.
    :raises requests.HTTPError: 500 — store unreachable, the token is **not**
        revoked; retry.
    """
    response = requests.delete(f"{SERVICE}/tokens/{jti}", headers=auth_headers())
    response.raise_for_status()


def revoke_subject(sub: str) -> int:
    """Revoke every active token of a subject.

    ``DELETE /subjects/{sub}/tokens``. This is the compromise path: tokens
    cannot be killed one by one because the caller does not know their ``jti``.

    :param sub: Subject whose tokens are killed.
    :return: Number of revoked tokens; already expired ones do not count.
    :raises requests.HTTPError: 500 — store unreachable, nothing was revoked.
    """
    response = requests.delete(f"{SERVICE}/subjects/{sub}/tokens", headers=auth_headers())
    response.raise_for_status()
    return response.json()["revoked"]


def main() -> None:
    """Full token lifecycle: issue, refresh, bulk revoke."""
    issued = issue_token("svc-a", ["svc-b"], with_refresh=True, claims={"role": "admin"})
    print("issued:", issued["token"][:32], "...")

    refreshed = refresh_tokens(issued["refresh_token"])
    print("refreshed:", refreshed["token"][:32], "...")

    revoked = revoke_subject("svc-a")
    print("revoked:", revoked)


if __name__ == "__main__":
    main()
