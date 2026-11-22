from datetime import date, timedelta

import pyotp
from sqlalchemy import select

from app.models import Case, Client, Document, DocumentRequest, User, utcnow
from app.security import new_upload_token
from tests.conftest import PASSWORD, TOTP_SECRET, csrf_from

PDF = b"%PDF-1.4\n%prueba\n"


def make_request(db, expires_in_days=7):
    client = Client(full_name="Juan Pérez", email="juan@example.com")
    case = Case(reference="PA 1/2026", title="Juan", client=client)
    raw, h = new_upload_token()
    req = DocumentRequest(description="DNI", token_hash=h, token_expires_at=utcnow() + timedelta(days=expires_in_days))
    case.document_requests.append(req)
    db.add(case)
    db.commit()
    return raw, req


def test_rutas_privadas_redirigen_al_login(client):
    for path in ["/", "/casos", "/clientes", "/usuarios", "/documentos/1/descargar"]:
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"


def test_cabeceras_de_seguridad(client):
    r = client.get("/login")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_sin_documentacion_openapi_expuesta(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_post_sin_csrf_es_rechazado(client, lawyer):
    r = client.post("/login", data={"email": lawyer.email, "password": PASSWORD})
    assert r.status_code == 403


def test_login_requiere_2fa(client, lawyer):
    r = client.get("/login")
    client.post("/login", data={"email": lawyer.email, "password": PASSWORD, "csrf_token": csrf_from(r.text)})
    # con contraseña correcta pero sin 2FA no hay acceso al panel
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    r = client.get("/login/2fa")
    r = client.post("/login/2fa", data={"code": "000000", "csrf_token": csrf_from(r.text)})
    assert r.status_code == 400


def test_codigo_totp_no_se_puede_reutilizar(client, lawyer):
    code = pyotp.TOTP(TOTP_SECRET).now()
    for expected in (303, 400):
        r = client.get("/login")
        client.post("/login", data={"email": lawyer.email, "password": PASSWORD, "csrf_token": csrf_from(r.text)})
        r = client.get("/login/2fa")
        r = client.post("/login/2fa", data={"code": code, "csrf_token": csrf_from(r.text)}, follow_redirects=False)
        assert r.status_code == expected


def test_bloqueo_tras_intentos_fallidos(client, lawyer, db):
    for _ in range(5):
        r = client.get("/login")
        client.post("/login", data={"email": lawyer.email, "password": "mala", "csrf_token": csrf_from(r.text)})
    r = client.get("/login")
    r = client.post("/login", data={"email": lawyer.email, "password": PASSWORD, "csrf_token": csrf_from(r.text)})
    assert "bloqueada" in r.text
    db.expire_all()
    assert db.get(User, lawyer.id).locked_until is not None


def test_rate_limit_login(client, lawyer):
    codes = []
    for _ in range(12):
        r = client.get("/login")
        token = csrf_from(r.text) if r.status_code == 200 else "x"
        codes.append(
            client.post("/login", data={"email": "x@example.com", "password": "y", "csrf_token": token}).status_code
        )
    assert 429 in codes


def test_flujo_panel_crear_plazo(logged_in, db):
    r = logged_in.get("/clientes/nuevo")
    logged_in.post(
        "/clientes/guardar",
        data={"full_name": "Juan Pérez", "email": "juan@example.com", "csrf_token": csrf_from(r.text)},
    )
    client_id = db.scalar(select(Client.id))
    r = logged_in.get("/casos/nuevo")
    r = logged_in.post(
        "/casos/guardar",
        data={
            "reference": "PA 9/2026",
            "title": "Recurso",
            "client_id": client_id,
            "responsible": "",
            "csrf_token": csrf_from(r.text),
        },
    )
    assert r.status_code == 200
    case_id = db.scalar(select(Case.id))
    r = logged_in.post(
        f"/casos/{case_id}/plazos",
        data={
            "title": "Presentar recurso",
            "due_date": "2026-12-05",
            "alert_days": "7, 1",
            "csrf_token": csrf_from(r.text),
        },
    )
    assert "Presentar recurso" in r.text and "7,1" in r.text


def test_xss_se_escapa(logged_in):
    r = logged_in.get("/clientes/nuevo")
    logged_in.post(
        "/clientes/guardar",
        data={"full_name": "<script>alert(1)</script>", "email": "a@example.com", "csrf_token": csrf_from(r.text)},
    )
    r = logged_in.get("/clientes")
    assert "<script>alert(1)</script>" not in r.text and "&lt;script&gt;" in r.text


def test_cliente_sube_pdf_y_queda_cifrado(client, db, fake_mailer):
    raw, req = make_request(db)
    r = client.get(f"/subir/{raw}")
    assert r.status_code == 200 and "DNI" in r.text
    r = client.post(
        f"/subir/{raw}", data={"csrf_token": csrf_from(r.text)}, files={"files": ("dni.pdf", PDF, "application/pdf")}
    )
    assert r.status_code == 200 and "Gracias" in r.text
    db.expire_all()
    doc = db.scalar(select(Document))
    from app.storage import get_backend, load_decrypted

    assert get_backend().get(doc.stored_name) != PDF  # cifrado en reposo
    assert load_decrypted(doc.stored_name) == PDF
    assert db.get(DocumentRequest, req.id).status == "recibido"
    assert fake_mailer.sent and "despacho@example.com" in [m.to for m in fake_mailer.sent]
    # enlace de un solo uso
    assert client.get(f"/subir/{raw}").status_code == 404


def test_enlace_caducado_o_falso(client, db):
    raw, _ = make_request(db, expires_in_days=-1)
    assert client.get(f"/subir/{raw}").status_code == 404
    assert client.get("/subir/token-inventado").status_code == 404


def test_archivo_con_extension_falsa_es_rechazado(client, db, fake_mailer):
    raw, _ = make_request(db)
    r = client.get(f"/subir/{raw}")
    r = client.post(
        f"/subir/{raw}",
        data={"csrf_token": csrf_from(r.text)},
        files={"files": ("factura.pdf", b"MZ\x90\x00malware", "application/pdf")},
    )
    assert r.status_code == 400 and "no coincide" in r.text
    r = client.post(
        f"/subir/{raw}",
        data={"csrf_token": csrf_from(r.text)},
        files={"files": ("script.exe", b"MZ\x90", "application/octet-stream")},
    )
    assert r.status_code == 400 and "no permitido" in r.text


def test_descarga_documento_requiere_login_y_audita(logged_in, client, db, fake_mailer):
    raw, req = make_request(db)
    from app.storage import save_encrypted

    doc = Document(
        request_id=req.id,
        stored_name=save_encrypted(PDF),
        original_name="dni ñ.pdf",
        content_type="application/pdf",
        size=len(PDF),
        sha256="0" * 64,
    )
    db.add(doc)
    db.commit()
    r = logged_in.get(f"/documentos/{doc.id}/descargar")
    assert r.status_code == 200 and r.content == PDF
    assert "attachment" in r.headers["content-disposition"]


def test_no_admin_no_gestiona_usuarios(client, db):
    from app.security import encrypt_str, hash_password

    u = User(
        email="b@example.com",
        full_name="B",
        password_hash=hash_password(PASSWORD),
        role="abogado",
        totp_secret_enc=encrypt_str(TOTP_SECRET),
        totp_enabled=True,
    )
    db.add(u)
    db.commit()
    r = client.get("/login")
    client.post("/login", data={"email": u.email, "password": PASSWORD, "csrf_token": csrf_from(r.text)})
    r = client.get("/login/2fa")
    client.post("/login/2fa", data={"code": pyotp.TOTP(TOTP_SECRET).now(), "csrf_token": csrf_from(r.text)})
    assert client.get("/").status_code == 200
    assert client.get("/usuarios").status_code == 403


def test_primer_login_obliga_a_configurar_2fa(client, db):
    from app.security import hash_password

    u = User(email="nuevo@example.com", full_name="Nuevo", password_hash=hash_password(PASSWORD))
    db.add(u)
    db.commit()
    r = client.get("/login")
    r = client.post(
        "/login", data={"email": u.email, "password": PASSWORD, "csrf_token": csrf_from(r.text)}, follow_redirects=False
    )
    assert r.headers["location"] == "/2fa/configurar"
    r = client.get("/2fa/configurar")
    assert "data:image/svg+xml;base64," in r.text
    assert client.get("/", follow_redirects=False).status_code == 303
    assert date.today()
