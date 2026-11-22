"""Crea el primer usuario administrador.  Uso: python -m scripts.create_admin correo@despacho.es "Nombre"."""

import argparse
import getpass
import sys

from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import User
from app.security import hash_password, password_policy_error


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("email")
    p.add_argument("full_name")
    args = p.parse_args()
    password = getpass.getpass("Contraseña (mín. 12, mayúsculas, minúsculas y números): ")
    if password_policy_error(password):
        print("La contraseña no cumple la política: mínimo 12 caracteres con mayúsculas, minúsculas y números.")
        return 1
    if getpass.getpass("Repita la contraseña: ") != password:
        print("Las contraseñas no coinciden.")
        return 1
    with SessionLocal() as db:
        email = args.email.strip().lower()
        if db.scalar(select(User.id).where(func.lower(User.email) == email)):
            print("Ya existe un usuario con ese correo.")
            return 1
        db.add(User(email=email, full_name=args.full_name, password_hash=hash_password(password), role="admin"))
        db.commit()
    print("Administrador creado. Configure la verificación en dos pasos en su primer inicio de sesión.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
