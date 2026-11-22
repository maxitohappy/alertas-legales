"""Crea un usuario administrador.

Uso local:       python -m scripts.create_admin correo@despacho.es "Nombre"
Uso producción:  python -m scripts.create_admin correo@despacho.es "Nombre" --produccion
                 (pide la cadena de conexión de forma oculta; no queda en el historial de la terminal)
"""

import argparse
import getpass
import os
import sys


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("email")
    p.add_argument("full_name")
    p.add_argument("--produccion", action="store_true", help="Pedir la cadena de conexión de la BD de producción")
    args = p.parse_args()

    if args.produccion:
        url = getpass.getpass("Pegue la cadena de conexión de Neon (no se verá) y pulse Enter: ").strip().strip('"')
        if not url.startswith(("postgresql://", "postgres://")):
            print("La cadena debe empezar por postgresql://")
            return 1
        os.environ["DATABASE_URL"] = url

    # Importar después de fijar DATABASE_URL para que el motor use la BD indicada.
    from sqlalchemy import func, select

    from app.db import SessionLocal
    from app.models import User
    from app.security import hash_password, password_policy_error

    password = getpass.getpass("Contraseña del usuario (mín. 12, mayúsculas, minúsculas y números): ")
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
