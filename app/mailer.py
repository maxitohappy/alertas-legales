"""Envío de correo por SMTP (Gmail / Google Workspace) con TLS obligatorio."""

import logging
import smtplib
import ssl
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from app.config import get_settings

log = logging.getLogger(__name__)


@dataclass
class Mail:
    to: str
    subject: str
    text: str
    html: str | None = None


class MailError(RuntimeError):
    pass


class SMTPMailer:
    def __init__(self, retries: int = 3):
        self.s = get_settings()
        self.retries = retries

    def send(self, mail: Mail) -> None:
        msg = EmailMessage()
        msg["From"] = formataddr((self.s.firm_name, self.s.sender))
        msg["To"] = mail.to
        msg["Subject"] = mail.subject.replace("\r", " ").replace("\n", " ")
        msg["Message-ID"] = make_msgid()
        msg.set_content(mail.text)
        if mail.html:
            msg.add_alternative(mail.html, subtype="html")
        context = ssl.create_default_context()  # valida certificado del servidor
        last_exc: Exception | None = None
        for attempt in range(1, self.retries + 1):
            try:
                with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=30) as smtp:
                    smtp.starttls(context=context)
                    smtp.login(self.s.smtp_user, self.s.smtp_password)
                    smtp.send_message(msg)
                return
            except smtplib.SMTPAuthenticationError as exc:
                raise MailError("Credenciales SMTP rechazadas") from exc
            except (smtplib.SMTPException, OSError) as exc:
                last_exc = exc
                log.warning("Fallo SMTP (intento %s/%s): %s", attempt, self.retries, type(exc).__name__)
                time.sleep(2 * attempt)
        raise MailError("No se pudo enviar el correo") from last_exc


@dataclass
class FakeMailer:
    """Para --dry-run y tests: no envía nada, solo guarda y muestra los mensajes."""

    echo: bool = False
    sent: list[Mail] = field(default_factory=list)

    def send(self, mail: Mail) -> None:
        self.sent.append(mail)
        if self.echo:
            print(f"\n=== [SIMULACIÓN] Para: {mail.to}\n    Asunto: {mail.subject}\n{mail.text}")


def get_mailer():
    return SMTPMailer()
