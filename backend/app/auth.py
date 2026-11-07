import hashlib
import hmac
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request
from app.database import run_query

# ---------------------------------------------------------------------------
# Password storage
# ---------------------------------------------------------------------------
# Passwords are hashed with Argon2id (memory-hard KDF, OWASP's first choice).
# argon2-cffi generates a random 16-byte salt per hash and stores the salt and
# the cost parameters inside the encoded hash ("$argon2id$v=19$m=...,t=...,p=...$salt$hash"),
# so no separate salt column is needed and parameters can be raised later.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _is_legacy_sha256(password_hash: str) -> bool:
    # Hashes created by the original implementation: unsalted SHA-256 hex.
    return not password_hash.startswith("$argon2")


def verify_password(password: str, password_hash: str) -> bool:
    if _is_legacy_sha256(password_hash):
        legacy = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(legacy, password_hash)
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    # True for legacy SHA-256 hashes and for Argon2 hashes created with
    # weaker parameters than the current ones. Used to upgrade on login.
    return _is_legacy_sha256(password_hash) or _hasher.check_needs_rehash(password_hash)


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
