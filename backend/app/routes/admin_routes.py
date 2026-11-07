from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app.database import run_query, get_conn
from app.auth import require_role, STAFF_ROLES, VALID_ROLES

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Authorization matrix (enforced server-side on every admin route):
#   /admin, /admin/grades, grade updates  -> admin, teacher, ta
#   user listing, role changes, search    -> admin only
require_staff = require_role(*STAFF_ROLES)
require_admin = require_role("admin")


@router.get("/admin", response_class=HTMLResponse)
def admin_home(request: Request, user=Depends(require_staff)):
    users_count = run_query("SELECT COUNT(*) as c FROM users", fetchone=True)
    submissions_count = run_query("SELECT COUNT(*) as c FROM submissions", fetchone=True)
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "user": user,
            "users_count": users_count["c"],
            "submissions_count": submissions_count["c"],
        },
    )


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, user=Depends(require_admin)):
    users = run_query("SELECT id, email, full_name, role FROM users ORDER BY id", fetchall=True)
    return templates.TemplateResponse("admin_users.html", {"request": request, "user": user, "users": users})


@router.post("/admin/users/{user_id}/role")
def update_role(user_id: int, role: str = Form(...), user=Depends(require_admin)):
    # 'role' is only the new value to assign; it is validated against an
    # allowlist and never used to decide whether the caller is authorized.
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400)
    # An admin cannot change their own role, so the system cannot be left
    # without an administrator by accident.
    if user_id == user["id"]:
        raise HTTPException(status_code=400)

    run_query("UPDATE users SET role=%s WHERE id=%s", (role, user_id), commit=True)
    return RedirectResponse("/admin/users", status_code=302)


@router.get("/admin/grades", response_class=HTMLResponse)
def admin_grades(request: Request, user=Depends(require_staff)):
    grades = run_query(
        """
        SELECT g.id, u.full_name as student_name, a.title as assignment_title, g.grade_value, g.feedback
        FROM grades g
        JOIN users u ON u.id = g.student_id
        JOIN assignments a ON a.id = g.assignment_id
        ORDER BY g.id DESC
        """,
        fetchall=True,
    )
    return templates.TemplateResponse("admin_grades.html", {"request": request, "user": user, "grades": grades})


@router.post("/admin/grades/{grade_id}/update")
def update_grade(
    grade_id: int,
    grade_value: str = Form(...),
    feedback: str = Form(...),
    user=Depends(require_staff),
):
    run_query(
        "UPDATE grades SET grade_value=%s, feedback=%s, grader_id=%s, status='published', "
        "updated_at=CURRENT_TIMESTAMP WHERE id=%s",
        (grade_value, feedback, user["id"], grade_id),
        commit=True,
    )
    return RedirectResponse("/admin/grades", status_code=302)


@router.get("/admin/search-users", response_class=HTMLResponse)
def search_users(request: Request, q: str = "", user=Depends(require_admin)):
    sql = f"SELECT id, email, full_name, role FROM users WHERE email ILIKE '%{q}%' OR full_name ILIKE '%{q}%'"
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
            users = [dict(zip(cols, r)) for r in rows]
    finally:
        conn.close()

    return templates.TemplateResponse("admin_users.html", {"request": request, "user": user, "users": users, "q": q})
