import hashlib
import secrets
from fastapi import HTTPException, Request
from app.database import run_query


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def create_session(user_id: int) -> str:
    token = secrets.token_hex(16)
    run_query(
        "INSERT INTO sessions (user_id, session_token) VALUES (%s, %s)",
        (user_id, token),
        commit=True,
    )
    return token


def get_user_from_session(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        return None
    session = run_query(
        """
        SELECT u.* FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token = %s
        """,
        (session_token,),
        fetchone=True,
    )
    return session


def clear_session(token: str):
    run_query("DELETE FROM sessions WHERE session_token = %s", (token,), commit=True)


# ---------------------------------------------------------------------------
# Authorization (server-side, deny by default)
# ---------------------------------------------------------------------------
# Protected routes declare their requirement as a FastAPI dependency, so the
# check runs before the handler body and cannot be skipped. The role is always
# read from the users row resolved via the session cookie, never from
# client-controlled data such as form fields or custom headers.

VALID_ROLES = ("student", "ta", "teacher", "admin")
STAFF_ROLES = ("admin", "teacher", "ta")


def require_user(request: Request):
    user = get_user_from_session(request)
    if not user:
        # Converted into a redirect to /login by the handler in main.py.
        raise HTTPException(status_code=401)
    return user


def require_role(*allowed_roles: str):
    def dependency(request: Request):
        user = require_user(request)
        if user["role"] not in allowed_roles:
            raise HTTPException(status_code=403)
        return user

    return dependency
