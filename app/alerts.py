"""Lógica pura de alertas: decide qué avisos corresponden a una fecha. Sin BD ni correo."""

from dataclasses import dataclass
from datetime import date, timedelta

from app.business_days import SpainCalendar

AVISO = "aviso"
VENCE_HOY = "vence_hoy"
VENCIDO = "vencido"
DOC_VENCIDO = "doc_vencido"
DOC_SOLICITUD = "doc_solicitud"


@dataclass(frozen=True)
class DueAlert:
    kind: str
    ref_id: int
    target_date: date  # clave de idempotencia
    due_date: date
    days_left: int


def alert_date_for(due: date, days_before: int, cal: SpainCalendar) -> date:
    """Fecha de aviso: due - n días; si es inhábil se adelanta al día hábil anterior."""
    return cal.previous_business_day(due - timedelta(days=days_before))


def deadline_alert(ref_id: int, due: date, alert_days: list[int], today: date, cal: SpainCalendar) -> DueAlert | None:
    """Alerta que corresponde hoy a un plazo pendiente, o None.

    - Vencido: alerta diaria (solo días hábiles).
    - Vence hoy: siempre.
    - Aviso previo: se toma la fecha de aviso más reciente que ya llegó (<= hoy). Así, si el proceso
      no corrió algún día, el aviso se recupera al día siguiente en lugar de perderse. La fecha de
      aviso es la clave de idempotencia, por lo que nunca se envía dos veces.
    """
    days_left = (due - today).days
    if days_left < 0:
        if not cal.is_business_day(today):
            return None
        return DueAlert(VENCIDO, ref_id, today, due, days_left)
    if days_left == 0:
        return DueAlert(VENCE_HOY, ref_id, due, due, 0)
    reached = [d for d in (alert_date_for(due, n, cal) for n in alert_days if n > 0) if d <= today]
    if not reached:
        return None
    return DueAlert(AVISO, ref_id, max(reached), due, days_left)


def document_request_due(last_sent: date | None, every_days: int, today: date) -> bool:
    """¿Toca enviar (o recordar) la solicitud de documento al cliente hoy?"""
    if last_sent is None:
        return True
    return (today - last_sent).days >= max(1, every_days)
