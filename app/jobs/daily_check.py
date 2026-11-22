"""Proceso diario. Uso:

python -m app.jobs.daily_check                      # revisa hoy y envía correos
python -m app.jobs.daily_check --date 2026-12-04    # simula otra fecha
python -m app.jobs.daily_check --dry-run            # no envía ni guarda nada, solo muestra
"""

import argparse
import logging
import sys
from datetime import date

from app.config import get_settings
from app.db import SessionLocal
from app.mailer import FakeMailer, get_mailer
from app.notifier import run_daily_check
from app.web import local_today


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Revisión diaria de plazos y documentos")
    parser.add_argument("--date", type=date.fromisoformat, help="Fecha a revisar (AAAA-MM-DD)")
    parser.add_argument("--dry-run", action="store_true", help="Simular sin enviar ni guardar")
    args = parser.parse_args(argv)

    settings = get_settings()
    today = args.date or local_today()
    if args.dry_run:
        mailer = FakeMailer(echo=True)
    elif not settings.smtp_configured:
        logging.error("SMTP_USER / SMTP_PASSWORD no configurados. Use --dry-run para simular.")
        return 2
    else:
        mailer = get_mailer()

    logging.info("Revisión del %s%s", today.strftime("%d.%m.%Y"), " (simulación)" if args.dry_run else "")
    with SessionLocal() as db:
        summary = run_daily_check(db, today, mailer, persist=not args.dry_run)

    logging.info(
        "Resúmenes enviados: %s | Acciones notificadas: %s | Solicitudes a clientes: %s",
        summary.digests_sent,
        summary.items_notified,
        summary.document_requests_sent,
    )
    for err in summary.errors:
        logging.error(err)
    return 1 if summary.errors else 0


if __name__ == "__main__":
    sys.exit(main())
