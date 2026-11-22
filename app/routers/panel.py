"""Panel de abogados: inicio, clientes, casos y plazos."""

from datetime import date, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.db import get_db
from app.deps import audit, current_user, require_admin
from app.models import Case, Client, Deadline, DocumentRequest, User, parse_alert_days, utcnow
from app.notifier import calendar
from app.storage import delete_stored
from app.web import flash, local_today, templates

router = APIRouter()


def _parse_date(value: str, field: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Fecha inválida en '{field}'") from exc


def _get(db: Session, model, obj_id: int):
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="No encontrado")
    return obj


# ---------------- Inicio ----------------
@router.get("/")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    today = local_today()
    deadlines = db.scalars(
        select(Deadline)
        .where(Deadline.status == "pendiente", Deadline.due_date <= today + timedelta(days=30))
        .options(joinedload(Deadline.case).joinedload(Case.client))
        .order_by(Deadline.due_date)
    ).all()
    pending_docs = db.scalars(
        select(DocumentRequest)
        .where(DocumentRequest.status == "pendiente")
        .options(joinedload(DocumentRequest.case).joinedload(Case.client))
        .order_by(DocumentRequest.due_date)
    ).all()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user": user, "today": today, "deadlines": deadlines, "pending_docs": pending_docs},
    )


# ---------------- Clientes ----------------
@router.get("/clientes")
def clients_list(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    clients = db.scalars(select(Client).order_by(Client.full_name)).all()
    return templates.TemplateResponse(request, "clients.html", {"user": user, "clients": clients})


@router.get("/clientes/nuevo")
def client_new(request: Request, user: User = Depends(current_user)):
    return templates.TemplateResponse(request, "client_form.html", {"user": user, "client": None})


@router.get("/clientes/{client_id}/editar")
def client_edit(client_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request, "client_form.html", {"user": user, "client": _get(db, Client, client_id)}
    )


@router.post("/clientes/guardar")
def client_save(
    request: Request,
    client_id: int | None = Form(None),
    full_name: str = Form(..., min_length=2, max_length=200),
    email: str = Form(..., max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    phone: str = Form("", max_length=50),
    gdpr_consent_at: str = Form(""),
    notes: str = Form("", max_length=5000),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    client = _get(db, Client, client_id) if client_id else Client()
    client.full_name = full_name.strip()
    client.email = email.strip().lower()
    client.phone = phone.strip()
    client.gdpr_consent_at = _parse_date(gdpr_consent_at, "consentimiento") if gdpr_consent_at else None
    client.notes = notes
    db.add(client)
    db.commit()
    audit(db, request, user.id, "cliente_guardado", f"cliente={client.id}")
    flash(request, "Cliente guardado.")
    return RedirectResponse("/clientes", status_code=303)


@router.post("/clientes/{client_id}/eliminar")
def client_delete(client_id: int, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Derecho de supresión (RGPD): borra el cliente, sus casos y los archivos cifrados."""
    client = _get(db, Client, client_id)
    stored = [d.stored_name for c in client.cases for r in c.document_requests for d in r.documents]
    db.delete(client)
    db.commit()
    for name in stored:
        delete_stored(name)
    audit(db, request, user.id, "cliente_eliminado", f"cliente={client_id} archivos={len(stored)}")
    flash(request, "Cliente y todos sus datos eliminados.")
    return RedirectResponse("/clientes", status_code=303)


# ---------------- Casos ----------------
@router.get("/casos")
def cases_list(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    cases = db.scalars(
        select(Case).options(joinedload(Case.client), joinedload(Case.responsible)).order_by(Case.created_at.desc())
    ).all()
    return templates.TemplateResponse(request, "cases.html", {"user": user, "cases": cases})


def _case_form_ctx(db: Session, user: User, case: Case | None):
    return {
        "user": user,
        "case": case,
        "clients": db.scalars(select(Client).order_by(Client.full_name)).all(),
        "lawyers": db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.full_name)).all(),
    }


@router.get("/casos/nuevo")
def case_new(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "case_form.html", _case_form_ctx(db, user, None))


@router.get("/casos/{case_id}/editar")
def case_edit(case_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "case_form.html", _case_form_ctx(db, user, _get(db, Case, case_id)))


@router.post("/casos/guardar")
def case_save(
    request: Request,
    case_id: int | None = Form(None),
    reference: str = Form(..., min_length=1, max_length=100),
    title: str = Form(..., min_length=2, max_length=200),
    court: str = Form("", max_length=200),
    matter: str = Form("", max_length=100),
    client_id: int = Form(...),
    responsible: str = Form("", pattern=r"^\d*$"),
    status: str = Form("abierto", pattern="^(abierto|cerrado)$"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    case = _get(db, Case, case_id) if case_id else Case()
    _get(db, Client, client_id)
    responsible_id = int(responsible) if responsible else None
    if responsible_id:
        _get(db, User, responsible_id)
    case.reference, case.title, case.court, case.matter = reference.strip(), title.strip(), court, matter
    case.client_id, case.responsible_id, case.status = client_id, responsible_id or None, status
    db.add(case)
    db.commit()
    audit(db, request, user.id, "caso_guardado", f"caso={case.id}")
    flash(request, "Caso guardado.")
    return RedirectResponse(f"/casos/{case.id}", status_code=303)


@router.get("/casos/{case_id}")
def case_detail(case_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = _get(db, Case, case_id)
    cal = calendar()
    warnings = {
        d.id: "Cae en día inhábil"
        for d in case.deadlines
        if d.status == "pendiente" and not cal.is_business_day(d.due_date)
    }
    return templates.TemplateResponse(
        request,
        "case_detail.html",
        {"user": user, "case": case, "today": local_today(), "warnings": warnings},
    )


# ---------------- Plazos ----------------
@router.post("/casos/{case_id}/plazos")
def deadline_create(
    case_id: int,
    request: Request,
    title: str = Form(..., min_length=2, max_length=200),
    due_date: str = Form(...),
    alert_days: str = Form("1", max_length=50),
    notes: str = Form("", max_length=5000),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _get(db, Case, case_id)
    try:
        days = parse_alert_days(alert_days)
    except ValueError as exc:
        flash(request, f"Días de aviso inválidos: {exc}", "error")
        return RedirectResponse(f"/casos/{case_id}", status_code=303)
    d = Deadline(
        case_id=case_id,
        title=title.strip(),
        due_date=_parse_date(due_date, "fecha límite"),
        alert_days=",".join(str(n) for n in days),
        notes=notes,
    )
    db.add(d)
    db.commit()
    audit(db, request, user.id, "plazo_creado", f"plazo={d.id}")
    flash(request, "Plazo registrado. El sistema avisará automáticamente.")
    return RedirectResponse(f"/casos/{case_id}", status_code=303)


@router.post("/plazos/{deadline_id}/completar")
def deadline_complete(
    deadline_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    d = _get(db, Deadline, deadline_id)
    d.status, d.completed_at = "completado", utcnow()
    db.commit()
    audit(db, request, user.id, "plazo_completado", f"plazo={d.id}")
    flash(request, "Plazo marcado como completado.")
    return RedirectResponse(f"/casos/{d.case_id}", status_code=303)


@router.post("/plazos/{deadline_id}/eliminar")
def deadline_delete(
    deadline_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    d = _get(db, Deadline, deadline_id)
    case_id = d.case_id
    db.delete(d)
    db.commit()
    audit(db, request, user.id, "plazo_eliminado", f"plazo={deadline_id}")
    flash(request, "Plazo eliminado.")
    return RedirectResponse(f"/casos/{case_id}", status_code=303)
