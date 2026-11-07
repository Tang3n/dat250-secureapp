from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.auth import get_user_from_session
from app.routes import (
    auth_routes,
    profile_routes,
    course_routes,
    assignment_routes,
    grade_routes,
    message_routes,
    admin_routes,
    utility_routes,
)

app = FastAPI(title="DAT250 SecureApp", debug=True)
templates = Jinja2Templates(directory="app/templates")

ERROR_PAGES = {
    400: ("Bad request", "The request contained invalid data."),
    403: ("Access denied", "You do not have permission to access this resource."),
    404: ("Not found", "The requested resource does not exist."),
}


@app.exception_handler(StarletteHTTPException)
def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # 401 raised by require_user(): keep the original UX and send the browser to login.
    if exc.status_code == 401:
        return RedirectResponse("/login", status_code=302)
    title, details = ERROR_PAGES.get(
        exc.status_code, ("Request failed", "The request could not be completed.")
    )
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "user": get_user_from_session(request),
            "title": title,
            "details": details,
        },
        status_code=exc.status_code,
    )


app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.mount("/uploads", StaticFiles(directory="app/uploads"), name="uploads")

app.include_router(auth_routes.router)
app.include_router(profile_routes.router)
app.include_router(course_routes.router)
app.include_router(assignment_routes.router)
app.include_router(grade_routes.router)
app.include_router(message_routes.router)
app.include_router(admin_routes.router)
app.include_router(utility_routes.router)
