"""Security regression tests for the vulnerabilities remediated in this repo.

Scope: this group member is responsible for two findings from Assignment 1:
  F3 - IDOR: any logged-in user could read any grade and any private message
  F4 - Second SQL injection in the admin user search (/admin/search-users)

Every finding has
  * negative tests - the original exploit from Assignment 1 must fail, and
  * positive tests - legitimate users can still use the functionality.

Run against the original code (main) these tests fail; against the fixed
code they pass. The other findings (F1, F2, F5, F6) are owned by other group
members and are covered by their own tests.
"""
from conftest import BASE_URL, login_seed, query_one

ALICE = 4


def email_of(db, user_id):
    return query_one(db, "SELECT email FROM users WHERE id=%s", (user_id,))["email"]


def grade_owned_by(db, user_id):
    return query_one(
        db, "SELECT id FROM grades WHERE student_id=%s ORDER BY id LIMIT 1", (user_id,)
    )


def grade_not_owned_by(db, user_id):
    return query_one(
        db, "SELECT id, student_id FROM grades WHERE student_id<>%s ORDER BY id LIMIT 1", (user_id,)
    )


def any_message(db):
    return query_one(
        db, "SELECT id, sender_id, recipient_id FROM messages ORDER BY id LIMIT 1"
    )


# ---------------------------------------------------------------------------
# F3 - IDOR on GET /grades/{id} and GET /messages/{id}
# ---------------------------------------------------------------------------

def test_f3_student_cannot_read_another_students_grade(db):
    other = grade_not_owned_by(db, ALICE)
    alice = login_seed("alice@student.uis.no")
    r = alice.get(f"{BASE_URL}/grades/{other['id']}", allow_redirects=False)
    assert r.status_code == 404
    # No grade content of the victim must leak in the 404 body.
    assert "Feedback" not in r.text and "Grade:" not in r.text


def test_f3_fresh_student_cannot_read_any_existing_grade(db, student):
    some_grade = query_one(db, "SELECT id FROM grades ORDER BY id LIMIT 1")
    r = student["session"].get(f"{BASE_URL}/grades/{some_grade['id']}", allow_redirects=False)
    assert r.status_code == 404


def test_f3_student_can_read_own_grade(db):
    own = grade_owned_by(db, ALICE)
    assert own, "seed is expected to contain a grade for Alice"
    alice = login_seed("alice@student.uis.no")
    r = alice.get(f"{BASE_URL}/grades/{own['id']}", allow_redirects=False)
    assert r.status_code == 200
    assert "Grade:" in r.text


def test_f3_staff_can_read_any_grade(db):
    other = grade_not_owned_by(db, ALICE)
    teacher = login_seed("teacher@dat250.local")
    r = teacher.get(f"{BASE_URL}/grades/{other['id']}", allow_redirects=False)
    assert r.status_code == 200


def test_f3_missing_grade_returns_404():
    alice = login_seed("alice@student.uis.no")
    r = alice.get(f"{BASE_URL}/grades/999999", allow_redirects=False)
    assert r.status_code == 404


def test_f3_outsider_cannot_read_private_message(db, student):
    msg = any_message(db)
    assert msg, "seed is expected to contain at least one message"
    r = student["session"].get(f"{BASE_URL}/messages/{msg['id']}", allow_redirects=False)
    assert r.status_code == 404
    assert "From:" not in r.text and "To:" not in r.text


def test_f3_sender_and_recipient_can_read_message(db):
    msg = any_message(db)
    for party in (msg["sender_id"], msg["recipient_id"]):
        sess = login_seed(email_of(db, party))
        r = sess.get(f"{BASE_URL}/messages/{msg['id']}", allow_redirects=False)
        assert r.status_code == 200, f"participant {party} must be able to read the message"


def test_f3_missing_message_returns_404():
    alice = login_seed("alice@student.uis.no")
    r = alice.get(f"{BASE_URL}/messages/999999", allow_redirects=False)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# F4 - Second SQL injection in GET /admin/search-users?q=
# ---------------------------------------------------------------------------

def test_f4_union_injection_does_not_leak_password_hashes():
    admin = login_seed("admin@dat250.local")
    payload = "%' UNION SELECT id, email, password_hash, role FROM users-- "
    r = admin.get(f"{BASE_URL}/admin/search-users", params={"q": payload}, allow_redirects=False)
    assert r.status_code == 200
    # The original exploit rendered every password_hash in place of full_name.
    assert "argon2" not in r.text.lower()


def test_f4_boolean_injection_does_not_dump_all_users():
    admin = login_seed("admin@dat250.local")
    # A classic tautology must be treated as a literal search term, matching
    # no one, rather than returning the whole users table.
    r = admin.get(f"{BASE_URL}/admin/search-users", params={"q": "' OR '1'='1"}, allow_redirects=False)
    assert r.status_code == 200
    assert "admin@dat250.local" not in r.text
    assert "alice@student.uis.no" not in r.text


def test_f4_legitimate_search_still_works():
    admin = login_seed("admin@dat250.local")
    r = admin.get(f"{BASE_URL}/admin/search-users", params={"q": "alice"}, allow_redirects=False)
    assert r.status_code == 200
    assert "alice@student.uis.no" in r.text


def test_f4_search_users_remains_admin_only(student):
    # The endpoint must stay admin-only (F2); a student is refused, so the
    # injection surface is not even reachable without admin rights.
    r = student["session"].get(f"{BASE_URL}/admin/search-users", params={"q": "a"}, allow_redirects=False)
    assert r.status_code == 403
