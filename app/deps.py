"""Dependencias comunes: usuario autenticado, roles, CSRF y auditoría."""

import time

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import AuditLog, User
from app.security import client_ip, csrf_valid


class LoginRequired(Exception):
    pass


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("user_id")
    if not uid:
        raise LoginRequired()
    last_seen = request.session.get("last_seen", 0)
    if time.time() - last_seen > get_settings().session_idle_minutes * 60:
        request.session.clear()
        raise LoginRequired()
    user = db.get(User, uid)
    if user is None or not user.is_active:
        request.session.clear()
        raise LoginRequired()
    request.session["last_seen"] = int(time.time())
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Acción reservada a administradores")
    return user


async def verify_csrf(request: Request) -> None:
    """Se aplica a todos los routers: todo POST debe traer un token CSRF válido."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        form = await request.form()
        if not csrf_valid(request, form.get("csrf_token")):
            raise HTTPException(status_code=403, detail="Token CSRF inválido. Recargue la página.")


def audit(db: Session, request: Request, user_id: int | None, action: str, detail: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, detail=detail[:500], ip=client_ip(request)))
    db.commit()
