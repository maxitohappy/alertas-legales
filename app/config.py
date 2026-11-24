"""Configuración leída exclusivamente desde variables de entorno (o archivo .env local)."""

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "development"
    firm_name: str = "Estudio Jurídico"
    app_base_url: str = "http://localhost:8000"

    secret_key: str
    encryption_key: str

    database_url: str = "sqlite:///./dev.db"

    timezone: str = "Europe/Madrid"
    holidays_subdiv: str | None = None

    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    mail_from: str = ""

    firm_alert_emails: str = ""

    storage_backend: str = "local"
    storage_local_path: str = "./data/uploads"
    s3_bucket: str = ""
    s3_endpoint_url: str = ""
    s3_access_key: str = ""
    s3_secret_key: str = ""
    s3_region: str = "auto"

    # Aviso inmediato a GitHub Actions para enviar los correos en cola (ver app/dispatch.py)
    github_dispatch_token: str = ""
    github_repo: str = ""

    # Adjuntar los documentos recibidos al aviso del despacho (límite total por correo)
    attach_received_documents: bool = True
    attach_max_total_mb: int = 18

    # Validez de la contraseña temporal enviada a un usuario nuevo o restablecida
    temp_password_hours: int = 72

    upload_max_mb: int = 10
    upload_token_days: int = 7
    session_idle_minutes: int = 30

    @field_validator("holidays_subdiv", mode="before")
    @classmethod
    def _empty_subdiv(cls, v):
        return v or None

    @field_validator("secret_key")
    @classmethod
    def _strong_secret(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY debe tener al menos 32 caracteres")
        return v

    @field_validator("github_repo")
    @classmethod
    def _valid_repo(cls, v: str) -> str:
        import re

        if v and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", v):
            raise ValueError("GITHUB_REPO debe tener el formato usuario/repositorio")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def firm_emails(self) -> list[str]:
        return [e.strip().lower() for e in self.firm_alert_emails.split(",") if e.strip()]

    @property
    def smtp_configured(self) -> bool:
        return bool(self.smtp_user and self.smtp_password)

    @property
    def sender(self) -> str:
        return self.mail_from or self.smtp_user

    @property
    def sqlalchemy_url(self) -> str:
        url = self.database_url
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://") :]
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg://" + url[len("postgresql://") :]
        return url


@lru_cache
def get_settings() -> Settings:
    return Settings()
