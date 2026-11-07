"""Security regression tests for the vulnerabilities remediated in this repo.

Scope: this group member is responsible for three findings from Assignment 1:
  F2 - Broken function-level access control on the admin endpoints
  F5 - Insecure password storage (unsalted SHA-256 -> Argon2id)
  F6 - Weak authentication & session management

Every finding has
  * negative tests - the original exploit from Assignment 1 must fail, and
  * positive tests - legitimate users can still use the functionality.

Run against the original code (main) these tests fail; against the fixed
code they pass. The remaining findings (F1, F3, F4) are owned by other group
members and are covered by their own tests.
"""
import hashlib

import requests

from conftest import (
    BASE_URL,
    SEED_PASSWORDS,
    latest_reset_token,
    login,
    login_seed,
    query,
    query_one,
    register,
)

ALICE, BOB = 4, 5


def user_role(db, email):
    return query_one(db, "SELECT role FROM users WHERE email=%s", (email,))["role"]


def grade_of(db, student_id):
    return query_one(db, "SELECT * FROM grades WHERE student_id=%s ORDER BY id LIMIT 1", (student_id,))


# ---------------------------------------------------------------------------
# F2 - Broken function-level access control on /admin/*
# ---------------------------------------------------------------------------

def test_f2_student_cannot_open_admin_pages(student):
    s = student["session"]
    for path in ("/admin", "/admin/users", "/admin/grades", "/admin/search-users?q=a"):
        r = s.get(f"{BASE_URL}{path}", allow_redirects=False)
        assert r.status_code == 403, path
        assert "alice@student.uis.no" not in r.text


def test_f2_student_cannot_change_roles(db, student):
    s = student["session"]
    r = s.post(f"{BASE_URL}/admin/users/{BOB}/role", data={"role": "admin"}, allow_redirects=False)
    assert r.status_code == 403
    # the forged x-role header from the original code must not help either
    r = s.post(
        f"{BASE_URL}/admin/users/{BOB}/role",
        data={"role": "admin"},
        headers={"x-role": "admin"},
        allow_redirects=False,
    )
    assert r.status_code == 403
    assert user_role(db, "bob@student.uis.no") == "student"


def test_f2_student_cannot_tamper_with_grades(db, student):
    before = grade_of(db, ALICE)
    r = student["session"].post(
        f"{BASE_URL}/admin/grades/{before['id']}/update",
        data={"grade_value": "F", "feedback": "PWNED by a student", "role": "admin"},
        allow_redirects=False,
    )
    assert r.status_code == 403
    after = grade_of(db, ALICE)
    assert (after["grade_value"], after["feedback"]) == (before["grade_value"], before["feedback"])


def test_f2_unauthenticated_admin_request_redirects_to_login():
    r = requests.get(f"{BASE_URL}/admin/users", allow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"


def test_f2_ta_can_grade_but_not_manage_users():
    ta = login_seed("ta@dat250.local")
    assert ta.get(f"{BASE_URL}/admin", allow_redirects=False).status_code == 200
    assert ta.get(f"{BASE_URL}/admin/grades", allow_redirects=False).status_code == 200
    assert ta.get(f"{BASE_URL}/admin/users", allow_redirects=False).status_code == 403
    r = ta.post(f"{BASE_URL}/admin/users/{BOB}/role", data={"role": "admin"}, allow_redirects=False)
    assert r.status_code == 403


def test_f2_teacher_can_still_update_grades(db):
    teacher = login_seed("teacher@dat250.local")
    before = grade_of(db, ALICE)
    try:
        r = teacher.post(
            f"{BASE_URL}/admin/grades/{before['id']}/update",
            data={"grade_value": "A", "feedback": "Regression test"},
            allow_redirects=False,
        )
        assert r.status_code == 302
        after = grade_of(db, ALICE)
        assert (after["grade_value"], after["feedback"]) == ("A", "Regression test")
        assert after["grader_id"] == 2
    finally:
        query(
            db,
            "UPDATE grades SET grade_value=%s, feedback=%s, grader_id=%s, status=%s WHERE id=%s",
            (before["grade_value"], before["feedback"], before["grader_id"], before["status"], before["id"]),
        )


def test_f2_admin_can_still_manage_roles(db):
    admin = login_seed("admin@dat250.local")
    target_email, _ = register()
    target_id = query_one(db, "SELECT id FROM users WHERE email=%s", (target_email,))["id"]

    assert target_email in admin.get(f"{BASE_URL}/admin/users").text
    r = admin.post(f"{BASE_URL}/admin/users/{target_id}/role", data={"role": "ta"}, allow_redirects=False)
    assert r.status_code == 302
    assert user_role(db, target_email) == "ta"

    # invalid role values and changing one's own role are rejected
    r = admin.post(f"{BASE_URL}/admin/users/{target_id}/role", data={"role": "superuser"}, allow_redirects=False)
    assert r.status_code == 400
    r = admin.post(f"{BASE_URL}/admin/users/1/role", data={"role": "student"}, allow_redirects=False)
    assert r.status_code == 400
    assert user_role(db, "admin@dat250.local") == "admin"


# ---------------------------------------------------------------------------
# F5 - Insecure password storage (unsalted SHA-256)
# ---------------------------------------------------------------------------

def test_f5_seed_hashes_are_argon2id(db):
    for row in query(db, "SELECT email, password_hash FROM users WHERE id <= 6"):
        assert row["password_hash"].startswith("$argon2id$"), row["email"]


def test_f5_new_passwords_are_salted_argon2id(db):
    e1, _ = register(password="SamePassword1!")
    e2, _ = register(password="SamePassword1!")
    h1 = query_one(db, "SELECT password_hash FROM users WHERE email=%s", (e1,))["password_hash"]
    h2 = query_one(db, "SELECT password_hash FROM users WHERE email=%s", (e2,))["password_hash"]
    assert h1.startswith("$argon2id$") and h2.startswith("$argon2id$")
    assert h1 != h2  # per-user random salt
    assert h1 != hashlib.sha256(b"SamePassword1!").hexdigest()


def test_f5_legacy_sha256_hash_is_upgraded_on_login(db):
    email, password = register()
    legacy = hashlib.sha256(password.encode()).hexdigest()
    query(db, "UPDATE users SET password_hash=%s WHERE email=%s", (legacy, email))
    login(email, password)  # still works with the legacy hash...
    new_hash = query_one(db, "SELECT password_hash FROM users WHERE email=%s", (email,))["password_hash"]
    assert new_hash.startswith("$argon2id$")  # ...and was migrated
    login(email, password)  # and works with the new hash


def test_f5_seed_accounts_can_log_in():
    for email in SEED_PASSWORDS:
        login_seed(email)


# ---------------------------------------------------------------------------
# F6 - Weak authentication & session management
# ---------------------------------------------------------------------------

def test_f6a_session_cookie_flags():
    r = requests.post(
        f"{BASE_URL}/login",
        data={"email": "charlie@student.uis.no", "password": "Charlie123"},
        allow_redirects=False,
    )
    cookie = r.headers["set-cookie"].lower()
    assert "session_token=" in cookie
    assert "httponly" in cookie
    assert "samesite=lax" in cookie
    assert "max-age=" in cookie


def test_f6a_expired_session_is_rejected(db, student):
    s = student["session"]
    assert s.get(f"{BASE_URL}/dashboard", allow_redirects=False).status_code == 200
    token = s.cookies.get("session_token")
    query(db, "UPDATE sessions SET created_at = NOW() - INTERVAL '9 hours' WHERE session_token=%s", (token,))
    r = s.get(f"{BASE_URL}/dashboard", allow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"


def test_f6b_login_does_not_reveal_whether_account_exists():
    unknown = requests.post(f"{BASE_URL}/login", data={"email": "nobody@nope.test", "password": "x"})
    wrong = requests.post(f"{BASE_URL}/login", data={"email": "admin@dat250.local", "password": "wrong"})
    assert unknown.status_code == wrong.status_code == 200
    assert unknown.text == wrong.text
    assert "Invalid email or password." in wrong.text


def test_f6b_reset_request_does_not_reveal_whether_account_exists():
    unknown = requests.post(f"{BASE_URL}/reset-password", data={"email": "nobody@nope.test"})
    known = requests.post(f"{BASE_URL}/reset-password", data={"email": "bob@student.uis.no"})
    assert unknown.text == known.text


def test_f6c_reset_token_is_random_hashed_and_single_use(db, student):
    email = student["email"]
    requests.post(f"{BASE_URL}/reset-password", data={"email": email})
    token = latest_reset_token(email)

    assert len(token) >= 40 and not token.isdigit()
    stored = query(db, "SELECT token FROM password_reset_tokens t JOIN users u ON u.id=t.user_id WHERE u.email=%s", (email,))
    assert [r["token"] for r in stored] == [hashlib.sha256(token.encode()).hexdigest()]

    # legitimate use works and logs out existing sessions
    r = requests.post(f"{BASE_URL}/reset-password/{token}", data={"new_password": "NewPassw0rd!"}, allow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"
    login(email, "NewPassw0rd!")
    r = student["session"].get(f"{BASE_URL}/dashboard", allow_redirects=False)
    assert r.status_code == 302, "old session must be invalidated after a password reset"

    # replaying the same token fails
    r = requests.post(f"{BASE_URL}/reset-password/{token}", data={"new_password": "Hacked123!"}, allow_redirects=False)
    assert r.status_code == 200 and "Invalid or expired token" in r.text
    login(email, "NewPassw0rd!")


def test_f6c_expired_and_superseded_tokens_are_rejected(db, student):
    email = student["email"]
    requests.post(f"{BASE_URL}/reset-password", data={"email": email})
    first = latest_reset_token(email)
    requests.post(f"{BASE_URL}/reset-password", data={"email": email})
    second = latest_reset_token(email)
    assert first != second

    r = requests.post(f"{BASE_URL}/reset-password/{first}", data={"new_password": "Hacked123!"}, allow_redirects=False)
    assert "Invalid or expired token" in r.text  # superseded by the newer request

    query(
        db,
        "UPDATE password_reset_tokens SET created_at = NOW() - INTERVAL '2 hours' WHERE token=%s",
        (hashlib.sha256(second.encode()).hexdigest(),),
    )
    r = requests.post(f"{BASE_URL}/reset-password/{second}", data={"new_password": "Hacked123!"}, allow_redirects=False)
    assert "Invalid or expired token" in r.text
    login(email, student["password"])


def test_f6c_time_based_token_guess_fails(student):
    import time

    requests.post(f"{BASE_URL}/reset-password", data={"email": student["email"]})
    now = int(time.time())
    for t in range(now - 3, now + 2):
        guess = str(t)[-6:]
        r = requests.post(f"{BASE_URL}/reset-password/{guess}", data={"new_password": "Hacked123!"}, allow_redirects=False)
        assert r.status_code == 200 and "Invalid or expired token" in r.text
    login(student["email"], student["password"])
