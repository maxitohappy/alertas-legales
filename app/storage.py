"""Validación y almacenamiento cifrado de documentos subidos por clientes."""

import hashlib
import io
import re
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings
from app.security import fernet

# extensión -> (content-type, firma de bytes iniciales)
ALLOWED_TYPES: dict[str, tuple[str, bytes]] = {
    "pdf": ("application/pdf", b"%PDF-"),
    "png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    "jpg": ("image/jpeg", b"\xff\xd8\xff"),
    "jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    "docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        b"PK\x03\x04",
    ),
}
MAX_FILES_PER_UPLOAD = 5


class UploadRejected(ValueError):
    pass


@dataclass
class ValidatedFile:
    original_name: str
    content_type: str
    data: bytes
    sha256: str


def safe_display_name(filename: str) -> str:
    """Elimina rutas y caracteres de control; el nombre solo se usa para mostrarlo."""
    name = Path(filename.replace("\\", "/")).name
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return name[:200] or "documento"


def validate_upload(filename: str, data: bytes) -> ValidatedFile:
    max_bytes = get_settings().upload_max_mb * 1024 * 1024
    if not data:
        raise UploadRejected("El archivo está vacío.")
    if len(data) > max_bytes:
        raise UploadRejected(f"El archivo supera el máximo de {get_settings().upload_max_mb} MB.")
    name = safe_display_name(filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_TYPES:
        raise UploadRejected("Tipo de archivo no permitido. Formatos aceptados: PDF, JPG, PNG, DOCX.")
    content_type, magic = ALLOWED_TYPES[ext]
    if not data.startswith(magic):
        raise UploadRejected("El contenido del archivo no coincide con su extensión.")
    if ext == "docx":
        _check_docx(data)
    return ValidatedFile(name, content_type, data, hashlib.sha256(data).hexdigest())


def _check_docx(data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            if "word/document.xml" not in names:
                raise UploadRejected("El archivo DOCX no es válido.")
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                raise UploadRejected("No se aceptan documentos con macros.")
            total = sum(i.file_size for i in zf.infolist())
            if total > 200 * 1024 * 1024:  # protección contra "zip bombs"
                raise UploadRejected("El archivo DOCX no es válido.")
    except zipfile.BadZipFile as exc:
        raise UploadRejected("El archivo DOCX no es válido.") from exc


class LocalStorage:
    def __init__(self, base: str):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)

    def _path(self, name: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", name):
            raise ValueError("Nombre de archivo inválido")
        return self.base / name

    def put(self, name: str, blob: bytes) -> None:
        self._path(name).write_bytes(blob)

    def get(self, name: str) -> bytes:
        return self._path(name).read_bytes()

    def delete(self, name: str) -> None:
        self._path(name).unlink(missing_ok=True)


class S3Storage:
    def __init__(self):
        import boto3

        s = get_settings()
        self.bucket = s.s3_bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=s.s3_endpoint_url or None,
            aws_access_key_id=s.s3_access_key,
            aws_secret_access_key=s.s3_secret_key,
            region_name=s.s3_region,
        )

    def put(self, name: str, blob: bytes) -> None:
        self.client.put_object(Bucket=self.bucket, Key=name, Body=blob)

    def get(self, name: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=name)["Body"].read()

    def delete(self, name: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=name)


def get_backend():
    s = get_settings()
    if s.storage_backend == "s3":
        return S3Storage()
    return LocalStorage(s.storage_local_path)


def save_encrypted(data: bytes) -> str:
    """Cifra con Fernet (AES-128-CBC + HMAC-SHA256) y guarda con un nombre aleatorio."""
    name = uuid.uuid4().hex
    get_backend().put(name, fernet().encrypt(data))
    return name


def load_decrypted(name: str) -> bytes:
    return fernet().decrypt(get_backend().get(name))


def delete_stored(name: str) -> None:
    get_backend().delete(name)
