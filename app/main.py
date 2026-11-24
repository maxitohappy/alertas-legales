"""Aplicación web del sistema de alertas legales."""

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.deps import LoginRequired, PasswordChangeRequired, verify_csrf
from app.routers import auth, client_upload, documents, panel, users
from app.web import templates

logging.basicConfig(level=logging.INFO)
settings = get_settings()

# Documentación OpenAPI deshabilitada: no exponer la superficie de la API.
app = FastAPI(title="Alertas Legales", docs_url=None, redoc_url=None, openapi_url=None)

MAX_BODY_BYTES = (settings.upload_max_mb * 5 + 1) * 1024 * 1024

CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        return PlainTextResponse("Solicitud demasiado grande", status_code=413)
    response = await call_next(request)
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"  # los enlaces de carga no se filtran por Referer
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if not request.url.path.startswith("/static"):
        h["Cache-Control"] = "no-store"
    if settings.is_production:
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="sesion",
    max_age=8 * 3600,
    same_site="lax",
    https_only=settings.is_production,
)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

csrf = [Depends(verify_csrf)]
app.include_router(auth.router, dependencies=csrf)
app.include_router(panel.router, dependencies=csrf)
app.include_router(documents.router, dependencies=csrf)
app.include_router(users.router, dependencies=csrf)
app.include_router(client_upload.router, dependencies=csrf)


@app.exception_handler(LoginRequired)
async def _login_required(request: Request, exc: LoginRequired):
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(PasswordChangeRequired)
async def _password_change_required(request: Request, exc: PasswordChangeRequired):
    return RedirectResponse("/cambiar-contrasena", status_code=303)


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    messages = {404: "No encontrado", 403: "Acceso denegado", 429: "Demasiados intentos"}
    detail = exc.detail if isinstance(exc.detail, str) else messages.get(exc.status_code, "Error")
    return templates.TemplateResponse(
        request, "error.html", {"status": exc.status_code, "detail": detail}, status_code=exc.status_code
    )


@app.get("/salud", include_in_schema=False)
def health():
    return {"ok": True}
