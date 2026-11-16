import hashlib
import hmac
import json
import os
import urllib.parse
from fastapi import Header, HTTPException, status


def verify_telegram_init_data(init_data: str, bot_token: str) -> dict | None:
    if not init_data or not bot_token:
        return None

    try:
        parsed_data = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
    except Exception:
        return None

    received_hash = parsed_data.pop("hash", None)
    if not received_hash:
        return None

    sorted_items = sorted(parsed_data.items(), key=lambda item: item[0])
    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted_items)

    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        return None

    user_raw = parsed_data.get("user")
    if not user_raw:
        return None

    try:
        user_data = json.loads(user_raw)
        return {
            "id": user_data.get("id"),
            "first_name": user_data.get("first_name"),
            "username": user_data.get("username"),
        }
    except Exception:
        return None


def get_current_tg_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("tma "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )

    init_data = authorization[4:].strip()
    bot_token = os.getenv("BOT_TOKEN", "")
    if not bot_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="BOT_TOKEN environment variable is not configured",
        )

    user = verify_telegram_init_data(init_data, bot_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Telegram initData",
        )

    return user
