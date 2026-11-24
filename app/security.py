"""Primitivas de seguridad: contraseñas, cifrado, 2FA, CSRF, tokens de carga y rate limiting."""

import hashlib
import hmac
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet
from fastapi import Request

from app.config import get_settings
from app.models import User, as_aware, utcnow

MIN_PASSWORD_LENGTH = 12
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15

_hasher = PasswordHasher()  # Argon2id con parámetros recomendados por OWASP
_DUMMY_HASH = _hasher.hash("contraseña-ficticia-para-igualar-tiempos")


# ---------- Contraseñas ----------
def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    """Verifica en tiempo similar exista o no el usuario (evita enumeración por tiempos)."""
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def generate_temp_password(length: int = 16) -> str:
    """Contraseña temporal aleatoria que cumple la política (sin caracteres que se confundan)."""
    lower, upper, digits = "abcdefghjkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789"
    alphabet = lower + upper + digits
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c in lower for c in pwd) and any(c in upper for c in pwd) and any(c in digits for c in pwd):
            return pwd


def password_policy_error(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres."
    if password.lower() == password or password.upper() == password or not any(c.isdigit() for c in password):
        return "La contraseña debe combinar mayúsculas, minúsculas y números."
    return None


# ---------- Bloqueo de cuenta ----------
def is_locked(user: User) -> bool:
    locked = as_aware(user.locked_until)
    return locked is not None and locked > utcnow()


def register_failed_login(user: User) -> None:
    user.failed_logins += 1
    if user.failed_logins >= MAX_FAILED_LOGINS:
        user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_logins = 0


def register_successful_login(user: User) -> None:
    user.failed_logins = 0
    user.locked_until = None


# ---------- Cifrado simétrico (datos en reposo) ----------
def fernet() -> Fernet:
    return Fernet(get_settings().encryption_key.encode())


def encrypt_str(value: str) -> str:
    return fernet().encrypt(value.encode()).decode()


def decrypt_str(value: str) -> str:
    return fernet().decrypt(value.encode()).decode()


# ---------- 2FA TOTP ----------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=get_settings().firm_name)


def verify_totp(user: User, code: str, secret: str | None = None) -> bool:
    """Acepta el código actual ±30 s y rechaza reutilizar un código ya usado (anti-replay)."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return False
    if secret is None:
        if not user.totp_secret_enc:
            return False
        secret = decrypt_str(user.totp_secret_enc)
    totp = pyotp.TOTP(secret)
    current_step = totp.timecode(datetime.now(UTC))
    for offset in (-1, 0, 1):
        step = current_step + offset
        if step <= (user.totp_last_step or 0):
            continue
        if hmac.compare_digest(totp.generate_otp(step), code):
            user.totp_last_step = step
            return True
    return False


# ---------- CSRF ----------
def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def csrf_valid(request: Request, submitted: str | None) -> bool:
    expected = request.session.get("csrf")
    return bool(expected and submitted and hmac.compare_digest(expected, submitted))


# ---------- Tokens de carga para clientes ----------
def new_upload_token() -> tuple[str, str]:
    """Devuelve (token_en_claro, hash). En BD solo se guarda el hash."""
    raw = secrets.token_urlsafe(32)
    return raw, hash_token(raw)


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------- Rate limiting en memoria ----------
class RateLimiter:
    """Ventana deslizante en memoria. Suficiente para una instancia; con varias usar Redis."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = RateLimiter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "desconocida"
