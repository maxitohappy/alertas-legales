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
