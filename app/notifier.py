"""Revisión diaria de casos: alertas al estudio y solicitudes de documentos a clientes."""

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app import alerts
from app.business_days import SpainCalendar
from app.config import get_settings
from app.mailer import Mail, MailError, mask_email
from app.models import Case, Deadline, DocumentRequest, Notification, utcnow
from app.security import new_upload_token
from app.web import local_date, render_email

log = logging.getLogger(__name__)

KIND_LABELS = {
    alerts.AVISO: "Aviso",
    alerts.VENCE_HOY: "VENCE HOY",
    alerts.VENCIDO: "VENCIDO",
    alerts.DOC_VENCIDO: "Documento no recibido",
}
KIND_ORDER = {alerts.VENCIDO: 0, alerts.VENCE_HOY: 1, alerts.DOC_VENCIDO: 2, alerts.AVISO: 3}


@dataclass
class DigestItem:
    kind: str
    ref_id: int
    target_date: date
    due_date: date
    days_left: int
    action: str
    case: Case

    @property
    def label(self) -> str:
        if self.kind == alerts.AVISO:
            return f"Aviso: faltan {self.days_left} día(s)"
        if self.kind == alerts.VENCIDO:
            return f"VENCIDO hace {-self.days_left} día(s)"
        if self.kind == alerts.DOC_VENCIDO:
            return f"Documento no recibido (venció hace {-self.days_left} día(s))"
        return KIND_LABELS[self.kind]


@dataclass
class Summary:
    digests_sent: int = 0
    items_notified: int = 0
    document_requests_sent: int = 0
    errors: list[str] = field(default_factory=list)


def calendar() -> SpainCalendar:
    return SpainCalendar(get_settings().holidays_subdiv)


def _already_sent(db: Session, kind: str, ref_id: int, target: date, recipient: str) -> bool:
    return (
        db.scalar(
            select(Notification.id).where(
                Notification.kind == kind,
                Notification.ref_id == ref_id,
                Notification.target_date == target,
                Notification.recipient == recipient,
            )
        )
        is not None
    )


def collect_firm_items(db: Session, today: date, cal: SpainCalendar) -> list[DigestItem]:
    items: list[DigestItem] = []
    deadlines = db.scalars(
        select(Deadline)
        .where(Deadline.status == "pendiente")
        .options(
            joinedload(Deadline.case).joinedload(Case.client), joinedload(Deadline.case).joinedload(Case.responsible)
        )
    ).all()
    for d in deadlines:
        try:
            days = d.alert_days_list
        except ValueError:
            days = [1]
        a = alerts.deadline_alert(d.id, d.due_date, days, today, cal)
        if a:
            items.append(DigestItem(a.kind, d.id, a.target_date, d.due_date, a.days_left, d.title, d.case))

    if cal.is_business_day(today):
        overdue_docs = db.scalars(
            select(DocumentRequest)
            .where(
                DocumentRequest.status == "pendiente",
                DocumentRequest.due_date.is_not(None),
                DocumentRequest.due_date < today,
            )
            .options(joinedload(DocumentRequest.case).joinedload(Case.client))
        ).all()
        for r in overdue_docs:
            items.append(
                DigestItem(
                    alerts.DOC_VENCIDO,
                    r.id,
                    today,
                    r.due_date,
                    (r.due_date - today).days,
                    f"Cliente debe aportar: {r.description}",
                    r.case,
                )
            )
    items.sort(key=lambda i: (KIND_ORDER[i.kind], i.due_date))
    return items


def recipients_for(item: DigestItem) -> set[str]:
    rec = set(get_settings().firm_emails)
    if item.case.responsible and item.case.responsible.is_active:
        rec.add(item.case.responsible.email.lower())
    return rec


def send_firm_digests(db: Session, today: date, mailer, cal: SpainCalendar, summary: Summary, persist: bool):
    per_recipient: dict[str, list[DigestItem]] = {}
    for item in collect_firm_items(db, today, cal):
        for r in recipients_for(item):
            if not _already_sent(db, item.kind, item.ref_id, item.target_date, r):
                per_recipient.setdefault(r, []).append(item)
    if not per_recipient and not get_settings().firm_emails:
        log.warning("FIRM_ALERT_EMAILS está vacío: configure al menos un correo del estudio.")

    for recipient, items in sorted(per_recipient.items()):
        urgent = sum(1 for i in items if i.kind in (alerts.VENCIDO, alerts.VENCE_HOY))
        subject = f"[{get_settings().firm_name}] {len(items)} acción(es) pendiente(s) — {today:%d.%m.%Y}"
        if urgent:
            subject = f"URGENTE: {subject}"
        text, html = render_email("digest", items=items, today=today)
        try:
            mailer.send(Mail(recipient, subject, text, html))
        except MailError as exc:
            summary.errors.append(f"Resumen a {mask_email(recipient)}: {exc}")
            continue
        summary.digests_sent += 1
        summary.items_notified += len(items)
        if persist:
            for i in items:
                db.add(Notification(kind=i.kind, ref_id=i.ref_id, target_date=i.target_date, recipient=recipient))
            db.commit()


def send_document_request(db: Session, req: DocumentRequest, mailer, today: date, persist: bool = True) -> None:
    """Genera un enlace nuevo (invalida el anterior) y lo envía al cliente. Lanza MailError."""
    s = get_settings()
    client = req.case.client
    raw, token_hash = new_upload_token()
    expires = utcnow() + timedelta(days=s.upload_token_days)
    link = f"{s.app_base_url.rstrip('/')}/subir/{raw}"
    reminder = req.sent_count > 0
    text, html = render_email(
        "document_request",
        client_name=client.full_name,
        description=req.description,
        due_date=req.due_date,
        link=link,
        expires=expires,
        reminder=reminder,
    )
    subject = ("Recordatorio: " if reminder else "") + f"{s.firm_name} necesita un documento suyo"
    mailer.send(Mail(client.email, subject, text, html))
    if persist:
        req.token_hash = token_hash
        req.token_expires_at = expires
        req.last_sent_at = utcnow()
        req.last_sent_on = today
        req.sent_count += 1
        db.add(
            Notification(kind=alerts.DOC_SOLICITUD, ref_id=req.id, target_date=today, recipient=client.email.lower())
        )
        db.commit()


def send_client_requests(db: Session, today: date, mailer, cal: SpainCalendar, summary: Summary, persist: bool):
    if not cal.is_business_day(today):
        return  # a los clientes solo se les escribe en días hábiles
    reqs = db.scalars(
        select(DocumentRequest)
        .join(DocumentRequest.case)
        .where(DocumentRequest.status == "pendiente", Case.status == "abierto")
        .options(joinedload(DocumentRequest.case).joinedload(Case.client))
    ).all()
    for req in reqs:
        client = req.case.client
        if not client.email:
            continue
        last = req.last_sent_on or local_date(req.last_sent_at)
        if not alerts.document_request_due(last, req.reminder_every_days, today):
            continue
        if _already_sent(db, alerts.DOC_SOLICITUD, req.id, today, client.email.lower()):
            continue
        try:
            send_document_request(db, req, mailer, today, persist)
            summary.document_requests_sent += 1
        except MailError as exc:
            summary.errors.append(f"Solicitud {req.id}: {exc}")


def notify_document_received(req: DocumentRequest, filenames: list[str], mailer) -> None:
    rec = set(get_settings().firm_emails)
    if req.case.responsible:
        rec.add(req.case.responsible.email.lower())
    text, html = render_email("document_received", req=req, case=req.case, filenames=filenames)
    for r in sorted(rec):
        mailer.send(Mail(r, f"Documento recibido — {req.case.client.full_name} ({req.case.reference})", text, html))


def run_daily_check(db: Session, today: date, mailer, persist: bool = True) -> Summary:
    cal = calendar()
    summary = Summary()
    send_firm_digests(db, today, mailer, cal, summary, persist)
    send_client_requests(db, today, mailer, cal, summary, persist)
    if not persist:
        db.rollback()
    return summary
