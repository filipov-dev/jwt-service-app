# Python — библиотека: pyotp (`pip install pyotp requests`)
import os
import pyotp
import requests

secret = os.environ["AUTH_TOTP_SECRET"]          # base32, без паддинга
service = os.environ.get("JWT_SERVICE_URL", "http://localhost:8080")

code = pyotp.TOTP(secret).now()                  # SHA-1, 6 знаков, шаг 30с

resp = requests.post(
    f"{service}/tokens",
    headers={"X-TOTP-Code": code, "Host": "example.com"},
    json={"sub": "svc-a", "aud": ["svc-b"]},
)
print(resp.status_code, resp.text)
