"""jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

Install: pip install pyotp requests
Env: AUTH_TOTP_SECRET (base32), JWT_SERVICE_URL (default http://localhost:8080).
See README.md for endpoints, error codes and client rules.
"""

import os

import pyotp
import requests

SECRET = os.environ["AUTH_TOTP_SECRET"]
SERVICE = os.environ.get("JWT_SERVICE_URL", "http://localhost:8080")

#: Sent as the Host header, becomes the "iss" claim.
ISSUER_HOST = "example.com"


def totp_code() -> str:
    """Fresh TOTP code: SHA-1, 6 digits, 30-second step."""
    return pyotp.TOTP(SECRET).now()


def auth_headers() -> dict:
    """Headers with a code computed right before the call."""
    return {"X-TOTP-Code": totp_code(), "Host": ISSUER_HOST}


def issue_token(
    sub: str,
    aud: list,
    with_refresh: bool = False,
    claims: dict = None,
) -> dict:
    """POST /tokens -> {"token", "refresh_token"?}."""
    payload = {"sub": sub, "aud": aud, "refresh": with_refresh}
    if claims:
        payload["claims"] = claims

    response = requests.post(f"{SERVICE}/tokens", headers=auth_headers(), json=payload)
    response.raise_for_status()
    return response.json()


def refresh_tokens(refresh_token: str) -> dict:
    """POST /tokens/refresh -> a new pair; the old refresh token is dead."""
    response = requests.post(
        f"{SERVICE}/tokens/refresh",
        headers=auth_headers(),
        json={"refresh_token": refresh_token},
    )
    response.raise_for_status()
    return response.json()


def revoke_token(jti: str) -> None:
    """DELETE /tokens/{jti} -> 204, idempotent."""
    response = requests.delete(f"{SERVICE}/tokens/{jti}", headers=auth_headers())
    response.raise_for_status()


def revoke_subject(sub: str) -> int:
    """DELETE /subjects/{sub}/tokens -> number of revoked tokens."""
    response = requests.delete(f"{SERVICE}/subjects/{sub}/tokens", headers=auth_headers())
    response.raise_for_status()
    return response.json()["revoked"]


def main() -> None:
    """Issue -> refresh -> revoke."""
    issued = issue_token("svc-a", ["svc-b"], with_refresh=True, claims={"role": "admin"})
    print("issued:", issued["token"][:32], "...")

    refreshed = refresh_tokens(issued["refresh_token"])
    print("refreshed:", refreshed["token"][:32], "...")

    revoked = revoke_subject("svc-a")
    print("revoked:", revoked)


if __name__ == "__main__":
    main()
