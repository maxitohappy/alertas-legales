"""Inicio de sesión con contraseña + 2FA TOTP obligatorio."""

import base64
import io
import time

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import audit
from app.models import User
from app.security import (
    client_ip,
    decrypt_str,
    encrypt_str,
    is_locked,
    new_totp_secret,
    rate_limiter,
    register_failed_login,
    register_successful_login,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.web import templates

router = APIRouter()
GENERIC_ERROR = "Correo o contraseña incorrectos."


def _rate_limit(request: Request, scope: str, limit: int = 10, window: int = 300) -> None:
    if not rate_limiter.allow(f"{scope}:{client_ip(request)}", limit, window):
        raise HTTPException(status_code=429, detail="Demasiados intentos. Espere unos minutos.")


def _start_session(request: Request, user: User) -> None:
    # Se regenera la sesión completa para evitar fijación de sesión.
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["last_seen"] = int(time.time())


@router.get("/login")
def login_form(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login(
    request: Request,
    email: str = Form(..., max_length=254),
    password: str = Form(..., max_length=256),
    db: Session = Depends(get_db),
):
    _rate_limit(request, "login")
    user = db.scalar(select(User).where(func.lower(User.email) == email.strip().lower()))
    ok = verify_password(user.password_hash if user else None, password)
    if user is None or not user.is_active:
        audit(db, request, None, "login_fallido", "usuario inexistente o inactivo")
        return templates.TemplateResponse(request, "login.html", {"error": GENERIC_ERROR}, status_code=400)
    if not ok:
        if not is_locked(user):
            register_failed_login(user)
            db.commit()
        audit(db, request, user.id, "login_fallido")
        return templates.TemplateResponse(request, "login.html", {"error": GENERIC_ERROR}, status_code=400)
    if is_locked(user):
        audit(db, request, user.id, "login_bloqueado")
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Cuenta bloqueada temporalmente por intentos fallidos. Inténtelo en 15 minutos."},
            status_code=400,
        )

    request.session.clear()
    request.session["pending_user"] = user.id
    request.session["pending_since"] = int(time.time())
    if user.totp_enabled:
        return RedirectResponse("/login/2fa", status_code=303)
    return RedirectResponse("/2fa/configurar", status_code=303)


def _pending_user(request: Request, db: Session) -> User:
    uid = request.session.get("pending_user")
    since = request.session.get("pending_since", 0)
    if not uid or time.time() - since > 300:
        request.session.clear()
        raise HTTPException(status_code=403, detail="La sesión de inicio expiró. Vuelva a iniciar sesión.")
    user = db.get(User, uid)
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return user


@router.get("/login/2fa")
def totp_form(request: Request, db: Session = Depends(get_db)):
    _pending_user(request, db)
    return templates.TemplateResponse(request, "login_2fa.html", {"error": None})


@router.post("/login/2fa")
def totp_verify(request: Request, code: str = Form(..., max_length=10), db: Session = Depends(get_db)):
    _rate_limit(request, "2fa")
    user = _pending_user(request, db)
    if is_locked(user):
        raise HTTPException(status_code=403, detail="Cuenta bloqueada temporalmente.")
    if not user.totp_enabled or not verify_totp(user, code):
        register_failed_login(user)
        db.commit()
        audit(db, request, user.id, "2fa_fallido")
        return templates.TemplateResponse(request, "login_2fa.html", {"error": "Código incorrecto."}, status_code=400)
    register_successful_login(user)
    db.commit()
    _start_session(request, user)
    audit(db, request, user.id, "login_ok")
    return RedirectResponse("/", status_code=303)


def _qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


@router.get("/2fa/configurar")
def totp_setup_form(request: Request, db: Session = Depends(get_db)):
    user = _pending_user(request, db)
    if user.totp_enabled:
        return RedirectResponse("/login/2fa", status_code=303)
    if not user.totp_secret_enc:
        user.totp_secret_enc = encrypt_str(new_totp_secret())
        db.commit()
    secret = decrypt_str(user.totp_secret_enc)
    uri = totp_uri(secret, user.email)
    return templates.TemplateResponse(
        request, "totp_setup.html", {"qr": _qr_data_uri(uri), "secret": secret, "error": None}
    )


@router.post("/2fa/configurar")
def totp_setup(request: Request, code: str = Form(..., max_length=10), db: Session = Depends(get_db)):
    _rate_limit(request, "2fa")
    user = _pending_user(request, db)
    if user.totp_enabled or not user.totp_secret_enc:
        return RedirectResponse("/login/2fa", status_code=303)
    if not verify_totp(user, code):
        db.commit()
        secret = decrypt_str(user.totp_secret_enc)
        return templates.TemplateResponse(
            request,
            "totp_setup.html",
            {"qr": _qr_data_uri(totp_uri(secret, user.email)), "secret": secret, "error": "Código incorrecto."},
            status_code=400,
        )
    user.totp_enabled = True
    register_successful_login(user)
    db.commit()
    _start_session(request, user)
    audit(db, request, user.id, "2fa_activado")
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    uid = request.session.get("user_id")
    request.session.clear()
    if uid:
        audit(db, request, uid, "logout")
    return RedirectResponse("/login", status_code=303)
