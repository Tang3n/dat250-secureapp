from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app.database import run_query
from app.auth import get_user_from_session, STAFF_ROLES

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/grades", response_class=HTMLResponse)
def grades(request: Request):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    grade_rows = run_query(
        """
        SELECT g.*, a.title as assignment_title
        FROM grades g
        JOIN assignments a ON a.id = g.assignment_id
        WHERE g.student_id=%s
        ORDER BY g.id DESC
        """,
        (user["id"],),
        fetchall=True,
    )
    return templates.TemplateResponse("grades.html", {"request": request, "user": user, "grades": grade_rows})


@router.get("/grades/{grade_id}", response_class=HTMLResponse)
def grade_detail(request: Request, grade_id: int):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)

    grade = run_query(
        """
        SELECT g.*, a.title as assignment_title, u.full_name as student_name
        FROM grades g
        JOIN assignments a ON a.id=g.assignment_id
        JOIN users u ON u.id=g.student_id
        WHERE g.id=%s
        """,
        (grade_id,),
        fetchone=True,
    )
    # Object-level authorization: a student may only read their own grade;
    # staff (admin/teacher/ta) may read any. A missing grade or another
    # student's grade both return 404, so ids cannot be probed for existence.
    if not grade or (user["role"] not in STAFF_ROLES and grade["student_id"] != user["id"]):
        raise HTTPException(status_code=404)
    return templates.TemplateResponse("grade_detail.html", {"request": request, "user": user, "grade": grade})
