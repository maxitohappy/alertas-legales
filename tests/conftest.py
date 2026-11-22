import os
import re
import tempfile

_tmp = tempfile.mkdtemp(prefix="alertas-test-")
os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
        "SECRET_KEY": "x" * 48,
        "ENCRYPTION_KEY": "ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg=",
        "STORAGE_BACKEND": "local",
        "STORAGE_LOCAL_PATH": f"{_tmp}/uploads",
        "FIRM_ALERT_EMAILS": "despacho@example.com",
        "HOLIDAYS_SUBDIV": "",
        "SMTP_USER": "",
        "SMTP_PASSWORD": "",
        "APP_BASE_URL": "https://alertas.example.com",
        "FIRM_NAME": "Despacho Test",
    }
)

import pyotp  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.mailer import FakeMailer  # noqa: E402
from app.models import User  # noqa: E402
from app.security import encrypt_str, hash_password, rate_limiter  # noqa: E402

TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
PASSWORD = "ClaveSegura2026!"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    rate_limiter.reset()
    yield


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


@pytest.fixture
def fake_mailer(monkeypatch):
    mailer = FakeMailer()
    import app.routers.client_upload as cu
    import app.routers.documents as docs

    monkeypatch.setattr(docs, "get_mailer", lambda: mailer)
    monkeypatch.setattr(cu, "get_mailer", lambda: mailer)
    return mailer


@pytest.fixture
def lawyer(db):
    u = User(
        email="abogada@example.com",
        full_name="Ana Abogada",
        password_hash=hash_password(PASSWORD),
        role="admin",
        totp_secret_enc=encrypt_str(TOTP_SECRET),
        totp_enabled=True,
    )
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def client():
    from app.main import app

    return TestClient(app)


def csrf_from(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "no se encontró el token CSRF"
    return m.group(1)


@pytest.fixture
def logged_in(client, lawyer):
    r = client.get("/login")
    r = client.post(
        "/login",
        data={"email": lawyer.email, "password": PASSWORD, "csrf_token": csrf_from(r.text)},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == "/login/2fa"
    r = client.get("/login/2fa")
    r = client.post(
        "/login/2fa",
        data={"code": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": csrf_from(r.text)},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == "/"
    return client
