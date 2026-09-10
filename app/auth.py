import hashlib
import hmac
import time
from typing import Optional
import bcrypt

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from app.config import SECRET_KEY
from app.database import get_setting, get_user_by_username, set_setting

# Default admin credentials if not yet set in DB
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "MGWnbc1yg7"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def init_auth():
    """Initializes admin user and password hash in settings if not present."""
    if not get_setting("admin_username"):
        set_setting("admin_username", DEFAULT_ADMIN_USER)
    if not get_setting("admin_password_hash"):
        set_setting("admin_password_hash", hash_password(DEFAULT_ADMIN_PASS))


def create_session_token(username: str) -> str:
    ts = str(int(time.time()))
    payload = f"{username}:{ts}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: Optional[str]) -> bool:
    if not token or ":" not in token:
        return False
    parts = token.split(":")
    if len(parts) != 3:
        return False
    user, ts_str, sig = parts
    payload = f"{user}:{ts_str}"
    expected_sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False
    try:
        ts = int(ts_str)
        if time.time() - ts > 30 * 86400:  # 30 days
            return False
    except ValueError:
        return False
    return True


def get_current_user(request: Request) -> Optional[str]:
    token = request.cookies.get("session_token")
    if verify_session_token(token):
        return token.split(":")[0]
    return None


def get_current_auth(request: Request) -> Optional[dict]:
    username = get_current_user(request)
    if not username:
        return None
    admin_user = get_setting("admin_username", DEFAULT_ADMIN_USER)
    if username.lower() == admin_user.lower():
        return {
            "role": "admin",
            "username": admin_user,
            "user_id": None,
        }

    user = get_user_by_username(username)
    if user and user.get("is_active", 1):
        return {
            "role": "user",
            "username": user["username"],
            "user_id": user["id"],
            "connection_id": user["connection_id"],
        }
    return None


def require_auth(request: Request) -> dict:
    auth = get_current_auth(request)
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Необходима авторизация",
        )
    return auth


def require_admin(request: Request) -> dict:
    auth = require_auth(request)
    if auth.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Доступ разрешен только администратору",
        )
    return auth
