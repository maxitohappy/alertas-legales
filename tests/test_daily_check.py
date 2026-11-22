from datetime import date

from sqlalchemy import select

from app.jobs import daily_check
from app.mailer import FakeMailer
from app.models import Case, Client, Deadline, DocumentRequest, Notification
from app.notifier import run_daily_check


def seed(db, lawyer=None):
    client = Client(full_name="Juan Pérez", email="juan@example.com")
    case = Case(reference="PA 123/2026", title="Juan Pérez", client=client, responsible=lawyer)
    case.deadlines.append(Deadline(title="Presentar recurso de libertad", due_date=date(2026, 12, 5), alert_days="1"))
    case.document_requests.append(DocumentRequest(description="Copia del DNI", reminder_every_days=2))
    db.add(case)
    db.commit()
    return case


def test_envia_alerta_al_estudio_el_dia_anterior_y_pide_documento(db, lawyer):
    seed(db, lawyer)
    mailer = FakeMailer()
    summary = run_daily_check(db, date(2026, 12, 4), mailer)
    assert not summary.errors
    to = sorted(m.to for m in mailer.sent)
    assert to == ["abogada@example.com", "despacho@example.com", "juan@example.com"]
    digest = next(m for m in mailer.sent if m.to == "despacho@example.com")
    assert "Presentar recurso de libertad" in digest.text and "05.12.2026" in digest.text
    req_mail = next(m for m in mailer.sent if m.to == "juan@example.com")
    assert "https://alertas.example.com/subir/" in req_mail.text


def test_no_alerta_antes_de_tiempo(db):
    seed(db)
    mailer = FakeMailer()
    run_daily_check(db, date(2026, 12, 3), mailer)
    assert all("recurso" not in m.text for m in mailer.sent)


def test_idempotente_no_duplica_correos(db):
    seed(db)
    m1, m2 = FakeMailer(), FakeMailer()
    run_daily_check(db, date(2026, 12, 4), m1)
    run_daily_check(db, date(2026, 12, 4), m2)
    assert len(m1.sent) == 2 and m2.sent == []


def test_recordatorio_documento_cada_n_dias_hasta_recibirlo(db):
    case = seed(db)
    req = case.document_requests[0]
    run_daily_check(db, date(2026, 12, 1), FakeMailer())
    m = FakeMailer()
    run_daily_check(db, date(2026, 12, 2), m)
    assert not any(x.to == "juan@example.com" for x in m.sent)
    m = FakeMailer()
    run_daily_check(db, date(2026, 12, 3), m)
    assert any(x.to == "juan@example.com" and x.subject.startswith("Recordatorio") for x in m.sent)
    req.status = "recibido"
    db.commit()
    m = FakeMailer()
    run_daily_check(db, date(2026, 12, 7), m)
    assert not any(x.to == "juan@example.com" for x in m.sent)


def test_plazo_completado_no_genera_alerta(db):
    case = seed(db)
    case.deadlines[0].status = "completado"
    db.commit()
    m = FakeMailer()
    run_daily_check(db, date(2026, 12, 4), m)
    assert all(x.to == "juan@example.com" for x in m.sent)


def test_dry_run_no_guarda_nada(db, capsys, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    seed(db)
    assert daily_check.main(["--date", "2026-12-04", "--dry-run"]) == 0
    assert "Presentar recurso de libertad" in capsys.readouterr().out
    db.expire_all()
    assert db.scalars(select(Notification)).all() == []
    assert db.scalars(select(DocumentRequest)).first().token_hash is None


def test_sin_smtp_el_envio_real_falla_con_codigo(db):
    assert daily_check.main(["--date", "2026-12-04"]) == 2


def test_en_github_actions_la_simulacion_no_publica_datos_personales(db, capsys, monkeypatch):
    seed(db)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert daily_check.main(["--date", "2026-12-04", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "juan@example.com" not in out and "Juan Pérez" not in out and "/subir/" not in out
    assert "j***@example.com" in out
