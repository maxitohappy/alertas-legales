"""Gestión de usuarios del despacho (solo administradores)."""

from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.deps import audit, require_admin
from app.dispatch import dispatch_enabled, trigger_queue_send
from app.models import User, utcnow
from app.security import encrypt_str, generate_temp_password, hash_password, password_policy_error
from app.web import flash, templates

router = APIRouter()


@router.get("/usuarios")
def users_list(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.full_name)).all()
    return templates.TemplateResponse(
        request, "users.html", {"user": user, "users": users, "temp_hours": get_settings().temp_password_hours}
    )


def _issue_temp_password(
    target: User, typed: str, send_email: bool, kind: str, background: BackgroundTasks
) -> str | None:
    """Asigna una contraseña temporal (escrita o generada) y, si se pide, la deja en cola para enviarla.

    Devuelve un mensaje de error o None. La contraseña en claro solo se guarda cifrada hasta enviarse.
    """
    typed = typed.strip()
    if not typed and not send_email:
        return "Escriba una contraseña temporal o marque «Enviar por correo» para generarla automáticamente."
    if typed and (err := password_policy_error(typed)):
        return f"Contraseña temporal no válida: {err}"
    password = typed or generate_temp_password()
    target.password_hash = hash_password(password)
    target.must_change_password = True
    target.temp_password_expires_at = utcnow() + timedelta(hours=get_settings().temp_password_hours)
    if send_email:
        target.pending_credentials_enc = encrypt_str(password)
        target.pending_credentials_kind = kind
        background.add_task(trigger_queue_send)
    else:
        target.pending_credentials_enc = target.pending_credentials_kind = None
    return None


def _when() -> str:
    return "en 1-2 minutos" if dispatch_enabled() else "en los próximos 15-20 minutos"


@router.post("/usuarios")
def user_create(
    request: Request,
    background: BackgroundTasks,
    full_name: str = Form(..., min_length=2, max_length=200),
    email: str = Form(..., max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    password: str = Form("", max_length=256),
    send_email: bool = Form(False),
    role: str = Form("abogado", pattern="^(abogado|admin)$"),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    if db.scalar(select(User.id).where(func.lower(User.email) == email)):
        flash(request, "Ya existe un usuario con ese correo.", "error")
        return RedirectResponse("/usuarios", status_code=303)
    new = User(full_name=full_name.strip(), email=email, role=role)  # la contraseña la asigna el helper
    if err := _issue_temp_password(new, password, send_email, "bienvenida", background):
        flash(request, err, "error")
        return RedirectResponse("/usuarios", status_code=303)
    db.add(new)
    db.commit()
    audit(db, request, user.id, "usuario_creado", f"usuario={new.id} rol={role} correo={send_email}")
    hours = get_settings().temp_password_hours
    if send_email:
        msg = f"Usuario creado. Su contraseña temporal (válida {hours} h) se enviará a {email} {_when()}."
    else:
        msg = f"Usuario creado. Comuníquele la contraseña temporal (válida {hours} h) por un canal seguro."
    flash(request, msg + " Al entrar configurará la verificación en dos pasos y creará su contraseña personal.")
    return RedirectResponse("/usuarios", status_code=303)


@router.post("/usuarios/{user_id}/estado")
def user_toggle(user_id: int, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404)
    if target.id == user.id:
        flash(request, "No puede desactivar su propia cuenta.", "error")
        return RedirectResponse("/usuarios", status_code=303)
    target.is_active = not target.is_active
    db.commit()
    audit(db, request, user.id, "usuario_estado", f"usuario={target.id} activo={target.is_active}")
    return RedirectResponse("/usuarios", status_code=303)


@router.post("/usuarios/{user_id}/reset-2fa")
def user_reset_2fa(user_id: int, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404)
    target.totp_enabled, target.totp_secret_enc, target.totp_last_step = False, None, 0
    target.session_version += 1  # móvil perdido o cambiado: cierra sus sesiones abiertas
    db.commit()
    audit(db, request, user.id, "2fa_reiniciado", f"usuario={target.id}")
    flash(request, "2FA reiniciado: el usuario lo configurará en su próximo inicio de sesión.")
    return RedirectResponse("/usuarios", status_code=303)


@router.post("/usuarios/{user_id}/restablecer-contrasena")
def user_reset_password(
    user_id: int,
    request: Request,
    background: BackgroundTasks,
    temp_password: str = Form("", max_length=256),
    send_email: bool = Form(False),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """El administrador asigna una contraseña temporal que el usuario debe cambiar al entrar."""
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404)
    if target.id == user.id:
        flash(request, "Para su propia cuenta use «Cambiar contraseña».", "error")
        return RedirectResponse("/usuarios", status_code=303)
    if err := _issue_temp_password(target, temp_password, send_email, "restablecimiento", background):
        flash(request, err, "error")
        return RedirectResponse("/usuarios", status_code=303)
    target.session_version += 1  # cierra sus sesiones abiertas
    target.failed_logins, target.locked_until = 0, None
    db.commit()
    audit(db, request, user.id, "clave_restablecida", f"usuario={target.id} correo={send_email}")
    if send_email:
        msg = f"Contraseña temporal de {target.full_name} restablecida: se enviará a {target.email} {_when()}."
    else:
        msg = f"Contraseña temporal asignada a {target.full_name}. Comuníquesela por un canal seguro."
    flash(request, msg + " Deberá cambiarla al iniciar sesión.")
    return RedirectResponse("/usuarios", status_code=303)
