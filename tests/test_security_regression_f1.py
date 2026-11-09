"""Security regression tests for F1 - vertical privilege escalation via mass
assignment on POST /profile/update.

In the original code the handler accepted a client-supplied `role` form field
and wrote it to the caller's own users row, so any student could promote
themselves to admin by adding `role=admin` to the profile form.

Every check has
  * negative tests - the original exploit from Assignment 1 must fail, and
  * positive tests - users can still edit their own profile fields.
"""
import pytest

from conftest import BASE_URL, login_seed, query_one


def role_of(db, email):
    return query_one(db, "SELECT role FROM users WHERE email=%s", (email,))["role"]


def profile_update(session, **fields):
    data = {"full_name": "Mallory Test", "phone": "", "address": "", "bio": ""}
    data.update(fields)
    return session.post(f"{BASE_URL}/profile/update", data=data, allow_redirects=False)


# ---------------------------------------------------------------------------
# Negative: the role field from Assignment 1 is ignored
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("target_role", ["admin", "teacher", "ta"])
def test_f1_student_cannot_escalate_role_via_profile_update(db, student, target_role):
    r = profile_update(student["session"], bio="escalation attempt", role=target_role)
    # The legitimate part of the request is still processed ...
    assert r.status_code == 302
    # ... but the privilege level in the database is unchanged.
    assert role_of(db, student["email"]) == "student"


def test_f1_admin_panel_stays_forbidden_after_escalation_attempt(student):
    profile_update(student["session"], role="admin")
    r = student["session"].get(f"{BASE_URL}/admin", allow_redirects=False)
    assert r.status_code == 403


def test_f1_profile_form_no_longer_carries_role_field(db, student):
    user_id = query_one(db, "SELECT id FROM users WHERE email=%s", (student["email"],))["id"]
    r = student["session"].get(f"{BASE_URL}/profile/{user_id}")
    assert r.status_code == 200
    assert 'name="role"' not in r.text


# ---------------------------------------------------------------------------
# Positive: profile editing still works and never changes the role
# ---------------------------------------------------------------------------

def test_f1_student_can_still_update_own_profile(db, student):
    r = profile_update(
        student["session"],
        full_name="Mallory Updated",
        phone="+47 12345678",
        address="Stavanger",
        bio="Bio changed",
    )
    assert r.status_code == 302
    row = query_one(
        db,
        "SELECT full_name, phone, address, bio, role FROM users WHERE email=%s",
        (student["email"],),
    )
    assert row["full_name"] == "Mallory Updated"
    assert row["phone"] == "+47 12345678"
    assert row["address"] == "Stavanger"
    assert row["bio"] == "Bio changed"
    assert row["role"] == "student"


def test_f1_staff_profile_update_does_not_change_their_role(db):
    # Saving the profile must neither demote nor otherwise touch the role of
    # an existing privileged account (the old code defaulted role to 'student').
    email = "teacher@dat250.local"
    before = query_one(
        db, "SELECT full_name, phone, address, bio FROM users WHERE email=%s", (email,)
    )
    teacher = login_seed(email)
    try:
        r = teacher.post(
            f"{BASE_URL}/profile/update",
            data={"full_name": before["full_name"], "bio": "temporary bio"},
            allow_redirects=False,
        )
        assert r.status_code == 302
        assert role_of(db, email) == "teacher"
        assert teacher.get(f"{BASE_URL}/admin", allow_redirects=False).status_code == 200
    finally:
        query_one(
            db,
            "UPDATE users SET full_name=%s, phone=%s, address=%s, bio=%s WHERE email=%s",
            (before["full_name"], before["phone"], before["address"], before["bio"], email),
        )
