"""Carga datos de demostración: caso de Juan Pérez con recurso a presentar el 05.12.2026.

El correo del cliente demo se toma de la variable DEMO_EMAIL (nunca se escribe en el código).
Uso: python -m scripts.seed_demo
"""

import os
import sys
from datetime import date

from sqlalchemy import select

from app.config import get_settings
from app.db import SessionLocal
from app.models import Case, Client, Deadline, DocumentRequest


def main() -> int:
    get_settings()
    demo_email = os.environ.get("DEMO_EMAIL") or _from_env_file("DEMO_EMAIL")
    if not demo_email:
        print("Defina DEMO_EMAIL en .env con el correo que recibirá las pruebas.")
        return 1
    with SessionLocal() as db:
        if db.scalar(select(Client.id).where(Client.full_name == "Juan Pérez")):
            print("Los datos demo ya existen.")
            return 0
        client = Client(full_name="Juan Pérez", email=demo_email.lower(), phone="", gdpr_consent_at=date(2026, 11, 1))
        case = Case(
            reference="PA 123/2026",
            title="Juan Pérez — procedimiento penal",
            court="Juzgado de Instrucción nº 5 de Madrid",
            matter="Penal",
            client=client,
        )
        case.deadlines.append(
            Deadline(title="Presentar recurso de libertad", due_date=date(2026, 12, 5), alert_days="1")
        )
        case.document_requests.append(
            DocumentRequest(
                description="Copia del DNI por ambas caras y certificado de empadronamiento",
                due_date=date(2026, 12, 10),
                reminder_every_days=2,
            )
        )
        db.add(case)
        db.commit()
    print("Datos demo creados: Juan Pérez · recurso de libertad 05.12.2026 (aviso 1 día antes).")
    return 0


def _from_env_file(key: str) -> str:
    try:
        with open(".env", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].split("#")[0].strip()
    except FileNotFoundError:
        pass
    return ""


if __name__ == "__main__":
    sys.exit(main())
