"""Cambia el nombre visible de un usuario.

Uso producción:  python -m scripts.rename_user correo@despacho.es "Nombre Correcto" --produccion
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

    from sqlalchemy import func, select

    from app.db import SessionLocal
    from app.models import User

    name = args.full_name.strip()
    if len(name) < 2:
        print("El nombre es demasiado corto.")
        return 1
    with SessionLocal() as db:
        user = db.scalar(select(User).where(func.lower(User.email) == args.email.strip().lower()))
        if user is None:
            print("No existe un usuario con ese correo.")
            return 1
        user.full_name = name
        db.commit()
    print(f"Nombre actualizado: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
