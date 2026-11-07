"""Shared fixtures for the security regression tests.

The tests run against a live instance started with `docker compose up --build`.
They talk to the app over HTTP (like an attacker would) and use the database
and MailHog only to observe state (e.g. "did the role really change?") and to
read password-reset emails.
"""
import os
import re
import uuid

import psycopg2
import psycopg2.extras
import pytest
import requests

BASE_URL = os.getenv("BASE_URL", "http://localhost:18181").rstrip("/")
MAILHOG_URL = os.getenv("MAILHOG_URL", "http://localhost:8025").rstrip("/")
DATABASE_URL = os.getenv("TEST_DATABASE_URL", "postgresql://dat250:dat250@localhost:5432/dat250")

SEED_PASSWORDS = {
    "admin@dat250.local": "Admin123",
    "teacher@dat250.local": "Teacher123",
    "ta@dat250.local": "TA123",
    "alice@student.uis.no": "Alice123",
    "bob@student.uis.no": "Bob123",
    "charlie@student.uis.no": "Charlie123",
}


@pytest.fixture(scope="session", autouse=True)
def app_is_running():
    try:
        requests.get(f"{BASE_URL}/login", timeout=5)
    except requests.ConnectionError:
        pytest.exit(f"App not reachable at {BASE_URL} - start it with `docker compose up --build`", 2)


@pytest.fixture(scope="session")
def db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    conn.autocommit = True
    yield conn
    conn.close()


def query(db, sql, params=None):
    with db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else None


def query_one(db, sql, params=None):
    rows = query(db, sql, params)
    return rows[0] if rows else None


def login(email, password):
    """Return a requests.Session logged in as the given user (asserts success)."""
    s = requests.Session()
    r = s.post(f"{BASE_URL}/login", data={"email": email, "password": password}, allow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].endswith("/dashboard"), f"login failed for {email}"
    return s


def login_seed(email):
    return login(email, SEED_PASSWORDS[email])


def register(password="Passw0rd!x"):
    """Register a fresh throwaway student and return (email, password)."""
    email = f"test-{uuid.uuid4().hex[:12]}@evil.test"
    r = requests.post(
        f"{BASE_URL}/register",
        data={"email": email, "full_name": "Mallory Test", "password": password},
        allow_redirects=False,
    )
    assert r.status_code == 302, "registration failed"
    return email, password


@pytest.fixture
def student():
    """A freshly registered student (the attacker in most tests)."""
    email, password = register()
    return {"email": email, "password": password, "session": login(email, password)}


def latest_reset_token(email):
    """Read the newest reset link sent to `email` from MailHog."""
    r = requests.get(f"{MAILHOG_URL}/api/v2/search", params={"kind": "to", "query": email}, timeout=5)
    r.raise_for_status()
    items = r.json()["items"]
    assert items, f"no email for {email} in MailHog"
    body = items[0]["Content"]["Body"].replace("=\r\n", "")
    match = re.search(r"/reset-password/(\S+)", body)
    assert match, "no reset link in email"
    return match.group(1)
