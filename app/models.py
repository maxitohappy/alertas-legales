from datetime import UTC, date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    true,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def as_aware(dt: datetime | None) -> datetime | None:
    """SQLite devuelve datetimes sin zona horaria; se asume UTC."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="abogado")  # admin | abogado
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    totp_secret_enc: Mapped[str | None] = mapped_column(String(500), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Contraseña inicial o restablecida por un administrador: el usuario debe cambiarla al entrar.
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Se incrementa al cambiar o restablecer la contraseña: invalida las demás sesiones abiertas.
    session_version: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Client(Base):
    __tablename__ = "clients"
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(254))
    phone: Mapped[str] = mapped_column(String(50), default="")
    gdpr_consent_at: Mapped[date | None] = mapped_column(Date, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    cases: Mapped[list["Case"]] = relationship(back_populates="client", cascade="all, delete-orphan")


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(String(100))  # nº de procedimiento
    title: Mapped[str] = mapped_column(String(200))
    court: Mapped[str] = mapped_column(String(200), default="")
    matter: Mapped[str] = mapped_column(String(100), default="")
    status: Mapped[str] = mapped_column(String(20), default="abierto")  # abierto | cerrado
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"))
    responsible_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    client: Mapped[Client] = relationship(back_populates="cases")
    responsible: Mapped[User | None] = relationship()
    deadlines: Mapped[list["Deadline"]] = relationship(
        back_populates="case", cascade="all, delete-orphan", order_by="Deadline.due_date"
    )
    document_requests: Mapped[list["DocumentRequest"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


def parse_alert_days(raw: str) -> list[int]:
    """'7, 3,1' -> [7, 3, 1]. Lanza ValueError si el formato no es válido."""
    values = set()
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        n = int(part)
        if n < 0 or n > 365:
            raise ValueError("Los días de aviso deben estar entre 0 y 365")
        values.add(n)
    if not values:
        raise ValueError("Indique al menos un día de aviso")
    return sorted(values, reverse=True)


class Deadline(Base):
    """Plazo o acción con fecha límite (p. ej. 'Presentar recurso')."""

    __tablename__ = "deadlines"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    due_date: Mapped[date] = mapped_column(Date, index=True)
    alert_days: Mapped[str] = mapped_column(String(50), default="1")  # p. ej. "7,3,1"
    status: Mapped[str] = mapped_column(String(20), default="pendiente")  # pendiente | completado
    notes: Mapped[str] = mapped_column(Text, default="")
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="deadlines")

    @property
    def alert_days_list(self) -> list[int]:
        return parse_alert_days(self.alert_days)


class DocumentRequest(Base):
    """Documento que el cliente debe aportar."""

    __tablename__ = "document_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(String(500))
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    reminder_every_days: Mapped[int] = mapped_column(Integer, default=3)
    status: Mapped[str] = mapped_column(String(20), default="pendiente")  # pendiente|recibido|cancelado
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sent_on: Mapped[date | None] = mapped_column(Date, nullable=True)  # día de revisión del último envío
    sent_count: Mapped[int] = mapped_column(Integer, default=0)
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Cola de correos: el panel no envía (Render gratis bloquea SMTP); lo hace GitHub Actions.
    send_now: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    received_notified: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    case: Mapped[Case] = relationship(back_populates="document_requests")
    documents: Mapped[list["Document"]] = relationship(back_populates="request", cascade="all, delete-orphan")


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("document_requests.id", ondelete="CASCADE"), index=True)
    stored_name: Mapped[str] = mapped_column(String(64), unique=True)
    original_name: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(100))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    request: Mapped[DocumentRequest] = relationship(back_populates="documents")


class Notification(Base):
    """Registro de envíos. La restricción única garantiza que una alerta no se envíe dos veces."""

    __tablename__ = "notifications"
    __table_args__ = (UniqueConstraint("kind", "ref_id", "target_date", "recipient", name="uq_notification"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(30))
    ref_id: Mapped[int] = mapped_column(Integer)
    target_date: Mapped[date] = mapped_column(Date)
    recipient: Mapped[str] = mapped_column(String(254))
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(50))
    detail: Mapped[str] = mapped_column(String(500), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
