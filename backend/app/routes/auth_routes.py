import hashlib
import secrets
from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app.auth import (
    DUMMY_PASSWORD_HASH,
    hash_password,
    verify_password,
    password_needs_rehash,
    create_session,
    clear_session,
    clear_user_sessions,
    get_user_from_session,
    set_session_cookie,
)
from app.config import RESET_TOKEN_TTL_SECONDS
from app.database import run_query
from app.email_service import send_reset_email

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# One message for every failed login, whatever the reason, so the response
# does not reveal whether an email address is registered.
LOGIN_FAILED = "Invalid email or password."
RESET_REQUESTED = "If an account with that email exists, a password reset link has been sent."


def _hash_reset_token(token: str) -> str:
    # Reset tokens are stored only as SHA-256 digests. A fast hash is
    # sufficient here because the token is 256 bits of randomness (unlike a
    # password it cannot be guessed); it means a database read does not reveal
    # usable reset links.
    return hashlib.sha256(token.encode()).hexdigest()


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = get_user_from_session(request)
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", response_class=HTMLResponse)
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = run_query("SELECT * FROM users WHERE email=%s", (email,), fetchone=True)
    # Always run one Argon2 verification, also for unknown emails, so the
    # response time does not reveal whether the account exists.
    password_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
    password_ok = verify_password(password, password_hash)
    if not user or not password_ok:
        return templates.TemplateResponse("login.html", {"request": request, "error": LOGIN_FAILED})

    # Transparent migration: the plaintext password is only available at
    # login, so legacy SHA-256 hashes (or Argon2 hashes with outdated cost
    # parameters) are replaced with a fresh Argon2id hash right here.
    if password_needs_rehash(user["password_hash"]):
        run_query(
            "UPDATE users SET password_hash=%s WHERE id=%s",
            (hash_password(password), user["id"]),
            commit=True,
        )

    token = create_session(user["id"])
    resp = RedirectResponse("/dashboard", status_code=302)
    set_session_cookie(resp, token)
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@router.post("/register", response_class=HTMLResponse)
def register(request: Request, email: str = Form(...), full_name: str = Form(...), password: str = Form(...)):
    existing = run_query("SELECT id FROM users WHERE email=%s", (email,), fetchone=True)
    if existing:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Email already exists."}
        )
    run_query(
        """
        INSERT INTO users (email, full_name, password_hash, role)
        VALUES (%s, %s, %s, 'student')
        """,
        (email, full_name, hash_password(password)),
        commit=True,
    )
    return RedirectResponse("/login", status_code=302)


@router.get("/logout")
def logout(request: Request):
    token = request.cookies.get("session_token")
    if token:
        clear_session(token)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("session_token")
    return resp


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request):
    return templates.TemplateResponse("reset_password.html", {"request": request, "mode": "request", "message": None})


@router.post("/reset-password", response_class=HTMLResponse)
def reset_password_request(request: Request, email: str = Form(...)):
    user = run_query("SELECT id FROM users WHERE email=%s", (email,), fetchone=True)
    if user:
        # 256-bit token from the OS CSPRNG instead of the last six digits of
        # the Unix time. Older outstanding tokens for the user are revoked so
        # only the most recent link works.
        token = secrets.token_urlsafe(32)
        run_query("DELETE FROM password_reset_tokens WHERE user_id=%s", (user["id"],), commit=True)
        run_query(
            "INSERT INTO password_reset_tokens (user_id, token) VALUES (%s, %s)",
            (user["id"], _hash_reset_token(token)),
            commit=True,
        )
        send_reset_email(email, token)

    # Same response whether or not the account exists (no enumeration).
    return templates.TemplateResponse(
        "reset_password.html",
        {"request": request, "mode": "request", "message": RESET_REQUESTED},
    )


@router.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_token_page(request: Request, token: str):
    return templates.TemplateResponse("reset_password.html", {"request": request, "mode": "set", "token": token, "message": None})


@router.post("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_token(request: Request, token: str, new_password: str = Form(...)):
    # Consume the token atomically: DELETE ... RETURNING both validates and
    # invalidates it in one statement, so a token works exactly once even
    # under concurrent requests, and only within its validity window.
    token_row = run_query(
        """
        DELETE FROM password_reset_tokens
        WHERE token=%s AND created_at > NOW() - make_interval(secs => %s)
        RETURNING user_id
        """,
        (_hash_reset_token(token), RESET_TOKEN_TTL_SECONDS),
        fetchone=True,
        commit=True,
    )
    if not token_row:
        return templates.TemplateResponse(
            "reset_password.html",
            {"request": request, "mode": "set", "token": token, "message": "Invalid or expired token"},
        )

    user_id = token_row["user_id"]
    run_query(
        "UPDATE users SET password_hash=%s WHERE id=%s",
        (hash_password(new_password), user_id),
        commit=True,
    )
    # Revoke any other outstanding reset tokens and log out all existing
    # sessions, so an attacker holding an old session loses access.
    run_query("DELETE FROM password_reset_tokens WHERE user_id=%s", (user_id,), commit=True)
    clear_user_sessions(user_id)
    return RedirectResponse("/login", status_code=302)
