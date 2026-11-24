"""Contraseñas: cambio obligatorio, cambio propio y restablecimiento por el administrador."""

import time

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import User
from app.security import encrypt_str, hash_password, verify_password
from tests.conftest import PASSWORD, TOTP_SECRET, csrf_from

TEMP = "Temporal2026Abc"
NEW = "MiClavePersonal2026"


def login(client: TestClient, email: str, password: str, secret: str = TOTP_SECRET, offset: int = 0):
    r = client.get("/login")
    client.post("/login", data={"email": email, "password": password, "csrf_token": csrf_from(r.text)})
    r = client.get("/login/2fa")
    # offset=1 usa el código del siguiente intervalo de 30 s (aceptado; evita reutilizar el mismo código)
    code = pyotp.TOTP(secret).at(time.time() + 30 * offset)
    return client.post("/login/2fa", data={"code": code, "csrf_token": csrf_from(r.text)}, follow_redirects=False)


def make_user(db, email="julian@example.com", password=TEMP, must_change=True, role="abogado"):
    u = User(
        email=email,
        full_name="Julián",
        password_hash=hash_password(password),
        role=role,
        totp_secret_enc=encrypt_str(TOTP_SECRET),
        totp_enabled=True,
        must_change_password=must_change,
    )
    db.add(u)
    db.commit()
    return u


def test_admin_crea_usuario_con_cambio_obligatorio(logged_in, db):
    r = logged_in.get("/usuarios")
    logged_in.post(
        "/usuarios",
        data={
            "full_name": "Julián",
            "email": "julian@example.com",
            "password": TEMP,
            "role": "abogado",
            "csrf_token": csrf_from(r.text),
        },
    )
    u = db.scalar(select(User).where(User.email == "julian@example.com"))
    assert u.must_change_password is True
    assert "Pendiente de cambio" in logged_in.get("/usuarios").text


def test_usuario_nuevo_debe_cambiar_la_contrasena_antes_de_usar_el_panel(client, db):
    make_user(db)
    r = login(client, "julian@example.com", TEMP)
    assert r.status_code == 303
    # cualquier página del panel lleva al cambio obligatorio
    for path in ["/", "/casos", "/clientes"]:
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/cambiar-contrasena"
    r = client.get("/cambiar-contrasena")
    assert "Cree su contraseña personal" in r.text
    token = csrf_from(r.text)
    # errores: temporal incorrecta, no coincide, débil, igual a la actual
    bad = [
        ({"current_password": "otra", "new_password": NEW, "confirm_password": NEW}, "no es correcta"),
        ({"current_password": TEMP, "new_password": NEW, "confirm_password": NEW + "x"}, "no coinciden"),
        ({"current_password": TEMP, "new_password": "corta", "confirm_password": "corta"}, "12 caracteres"),
        ({"current_password": TEMP, "new_password": TEMP, "confirm_password": TEMP}, "distinta"),
    ]
    for data, msg in bad:
        r = client.post("/cambiar-contrasena", data={**data, "csrf_token": token})
        assert r.status_code == 400 and msg in r.text
    r = client.post(
        "/cambiar-contrasena",
        data={"current_password": TEMP, "new_password": NEW, "confirm_password": NEW, "csrf_token": token},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert client.get("/").status_code == 200
    db.expire_all()
    u = db.scalar(select(User).where(User.email == "julian@example.com"))
    assert u.must_change_password is False and verify_password(u.password_hash, NEW)


def test_usuario_cambia_su_contrasena_y_se_cierran_sus_otras_sesiones(db):
    from app.main import app

    make_user(db, password=PASSWORD, must_change=False)
    pc1, pc2 = TestClient(app), TestClient(app)
    assert login(pc1, "julian@example.com", PASSWORD).status_code == 303
    assert login(pc2, "julian@example.com", PASSWORD, offset=1).status_code == 303
    assert pc2.get("/").status_code == 200
    r = pc1.get("/cambiar-contrasena")
    assert "Cambiar contraseña" in r.text
    pc1.post(
        "/cambiar-contrasena",
        data={
            "current_password": PASSWORD,
            "new_password": NEW,
            "confirm_password": NEW,
            "csrf_token": csrf_from(r.text),
        },
    )
    assert pc1.get("/").status_code == 200  # la sesión que cambió sigue abierta
    r = pc2.get("/", follow_redirects=False)  # la otra queda cerrada
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_admin_restablece_contrasena_olvidada(logged_in, db):
    from app.main import app

    u = make_user(db, password=PASSWORD, must_change=False)
    julian = TestClient(app)
    assert login(julian, "julian@example.com", PASSWORD, offset=1).status_code == 303
    u.failed_logins, u.locked_until = 3, None
    db.commit()
    r = logged_in.get("/usuarios")
    r = logged_in.post(
        f"/usuarios/{u.id}/restablecer-contrasena", data={"temp_password": TEMP, "csrf_token": csrf_from(r.text)}
    )
    assert "Contraseña temporal asignada" in r.text
    db.expire_all()
    u = db.get(User, u.id)
    assert u.must_change_password and verify_password(u.password_hash, TEMP) and u.failed_logins == 0
    # la sesión abierta de Julián se cierra
    assert julian.get("/", follow_redirects=False).headers["location"] == "/login"


def test_restablecer_exige_contrasena_temporal_robusta_y_no_sirve_para_uno_mismo(logged_in, lawyer, db):
    u = make_user(db, must_change=False)
    r = logged_in.get("/usuarios")
    r = logged_in.post(
        f"/usuarios/{u.id}/restablecer-contrasena", data={"temp_password": "debil", "csrf_token": csrf_from(r.text)}
    )
    assert "no válida" in r.text
    r = logged_in.post(
        f"/usuarios/{lawyer.id}/restablecer-contrasena",
        data={"temp_password": TEMP, "csrf_token": csrf_from(r.text)},
    )
    assert "Cambiar contraseña" in r.text


def test_un_abogado_no_puede_restablecer_contrasenas(client, db):
    make_user(db, password=PASSWORD, must_change=False)
    other = make_user(db, email="otro@example.com", must_change=False)
    login(client, "julian@example.com", PASSWORD)
    r = client.get("/")
    r = client.post(
        f"/usuarios/{other.id}/restablecer-contrasena", data={"temp_password": TEMP, "csrf_token": csrf_from(r.text)}
    )
    assert r.status_code == 403


# ---------- Contraseña temporal enviada por correo ----------


def test_alta_genera_contrasena_y_la_envia_cifrada_por_la_cola(logged_in, db, fake_mailer, monkeypatch):
    from datetime import date

    import app.routers.users as users_router
    from app.notifier import run_queue

    calls = []
    monkeypatch.setattr(users_router, "trigger_queue_send", lambda: calls.append("x") or True)
    r = logged_in.get("/usuarios")
    r = logged_in.post(
        "/usuarios",
        data={
            "full_name": "Julián",
            "email": "julian@example.com",
            "send_email": "true",
            "role": "abogado",
            "csrf_token": csrf_from(r.text),
        },
    )
    assert "se enviará a julian@example.com" in r.text and calls == ["x"]
    assert "Correo en cola" in logged_in.get("/usuarios").text
    db.expire_all()
    u = db.scalar(select(User).where(User.email == "julian@example.com"))
    assert u.must_change_password and u.temp_password_expires_at is not None
    assert u.pending_credentials_enc and "julian" not in u.pending_credentials_enc  # guardada cifrada

    summary = run_queue(db, date.today(), fake_mailer)
    assert summary.credentials_sent == 1
    mail = fake_mailer.sent[0]
    assert mail.to == "julian@example.com" and "Su acceso a" in mail.subject
    password = mail.text.split("Contraseña temporal:")[1].split()[0]
    assert verify_password(u.password_hash, password)  # la del correo es la que funciona
    assert "Google Authenticator" in mail.text
    db.expire_all()
    assert db.get(User, u.id).pending_credentials_enc is None  # se borra tras enviarla
    run_queue(db, date.today(), fake_mailer)
    assert len(fake_mailer.sent) == 1  # no se reenvía


def test_alta_sin_correo_ni_contrasena_es_rechazada(logged_in, db):
    r = logged_in.get("/usuarios")
    r = logged_in.post(
        "/usuarios",
        data={"full_name": "Julián", "email": "julian@example.com", "role": "abogado", "csrf_token": csrf_from(r.text)},
    )
    assert "marque" in r.text
    assert db.scalar(select(User).where(User.email == "julian@example.com")) is None


def test_restablecer_por_correo_envia_nueva_temporal(logged_in, db, fake_mailer, monkeypatch):
    from datetime import date

    import app.routers.users as users_router
    from app.notifier import run_queue

    monkeypatch.setattr(users_router, "trigger_queue_send", lambda: True)
    u = make_user(db, password=PASSWORD, must_change=False)
    r = logged_in.get("/usuarios")
    logged_in.post(
        f"/usuarios/{u.id}/restablecer-contrasena", data={"send_email": "true", "csrf_token": csrf_from(r.text)}
    )
    run_queue(db, date.today(), fake_mailer)
    mail = fake_mailer.sent[0]
    assert "Nueva contraseña temporal" in mail.subject and "Google Authenticator" not in mail.text
    db.expire_all()
    password = mail.text.split("Contraseña temporal:")[1].split()[0]
    assert verify_password(db.get(User, u.id).password_hash, password)


def test_contrasena_temporal_caducada_no_permite_entrar(client, db):
    from datetime import timedelta

    from app.models import utcnow

    u = make_user(db)
    u.temp_password_expires_at = utcnow() - timedelta(hours=1)
    db.commit()
    r = client.get("/login")
    r = client.post("/login", data={"email": u.email, "password": TEMP, "csrf_token": csrf_from(r.text)})
    assert r.status_code == 400 and "caducado" in r.text


def test_contrasena_temporal_generada_cumple_la_politica():
    from app.security import generate_temp_password, password_policy_error

    for _ in range(50):
        assert password_policy_error(generate_temp_password()) is None


def test_registros_de_actions_no_muestran_la_contrasena(db, capsys, monkeypatch):
    from app.jobs import daily_check
    from app.security import encrypt_str as enc

    u = make_user(db)
    u.pending_credentials_enc, u.pending_credentials_kind = enc("SecretoVisible99"), "bienvenida"
    db.commit()
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert daily_check.main(["--solo-cola", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "SecretoVisible99" not in out and "julian@example.com" not in out
