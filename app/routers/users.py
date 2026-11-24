"""Gestión de usuarios del despacho (solo administradores)."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import audit, require_admin
from app.models import User
from app.security import hash_password, password_policy_error
from app.web import flash, templates

router = APIRouter()


@router.get("/usuarios")
def users_list(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.full_name)).all()
    return templates.TemplateResponse(request, "users.html", {"user": user, "users": users})


@router.post("/usuarios")
def user_create(
    request: Request,
    full_name: str = Form(..., min_length=2, max_length=200),
    email: str = Form(..., max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    password: str = Form(..., max_length=256),
    role: str = Form("abogado", pattern="^(abogado|admin)$"),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    if err := password_policy_error(password):
        flash(request, err, "error")
        return RedirectResponse("/usuarios", status_code=303)
    if db.scalar(select(User.id).where(func.lower(User.email) == email)):
        flash(request, "Ya existe un usuario con ese correo.", "error")
        return RedirectResponse("/usuarios", status_code=303)
    new = User(
        full_name=full_name.strip(),
        email=email,
        password_hash=hash_password(password),
        role=role,
        must_change_password=True,  # solo el usuario conocerá su contraseña definitiva
    )
    db.add(new)
    db.commit()
    audit(db, request, user.id, "usuario_creado", f"usuario={new.id} rol={role}")
    flash(
        request,
        "Usuario creado. En su primer inicio de sesión configurará la verificación en dos pasos "
        "y deberá cambiar la contraseña inicial.",
    )
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
    temp_password: str = Form(..., max_length=256),
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
    if err := password_policy_error(temp_password):
        flash(request, f"Contraseña temporal no válida: {err}", "error")
        return RedirectResponse("/usuarios", status_code=303)
    target.password_hash = hash_password(temp_password)
    target.must_change_password = True
    target.session_version += 1  # cierra sus sesiones abiertas
    target.failed_logins, target.locked_until = 0, None
    db.commit()
    audit(db, request, user.id, "clave_restablecida", f"usuario={target.id}")
    flash(
        request,
        f"Contraseña temporal asignada a {target.full_name}. Comuníquesela por un canal distinto al correo: "
        "deberá cambiarla al iniciar sesión.",
    )
    return RedirectResponse("/usuarios", status_code=303)
