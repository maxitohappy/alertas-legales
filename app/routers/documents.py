"""Solicitudes de documentos a clientes y descarga de documentos recibidos."""

from datetime import date
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import audit, current_user
from app.models import Case, Document, DocumentRequest, User
from app.storage import load_decrypted
from app.web import flash

router = APIRouter()


@router.post("/casos/{case_id}/solicitudes")
def request_create(
    case_id: int,
    request: Request,
    description: str = Form(..., min_length=3, max_length=500),
    due_date: str = Form(""),
    reminder_every_days: int = Form(3, ge=1, le=30),
    send_now: bool = Form(False),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404)
    try:
        due = date.fromisoformat(due_date) if due_date else None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Fecha inválida") from exc
    req = DocumentRequest(
        case_id=case.id, description=description.strip(), due_date=due, reminder_every_days=reminder_every_days
    )
    db.add(req)
    db.commit()
    audit(db, request, user.id, "solicitud_creada", f"solicitud={req.id}")
    if send_now:
        _send(db, request, req)
    else:
        flash(request, "Solicitud registrada. Se enviará al cliente en la próxima revisión diaria.")
    return RedirectResponse(f"/casos/{case.id}", status_code=303)


def _send(db: Session, request: Request, req: DocumentRequest) -> None:
    """Deja el correo en cola; GitHub Actions lo envía en los próximos minutos."""
    req.send_now = True
    db.commit()
    flash(request, f"Solicitud en cola: se enviará a {req.case.client.email} en los próximos 15-20 minutos.")


@router.post("/solicitudes/{req_id}/enviar")
def request_send(req_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    req = db.get(DocumentRequest, req_id)
    if req is None or req.status != "pendiente":
        raise HTTPException(status_code=404)
    _send(db, request, req)
    audit(db, request, user.id, "solicitud_enviada", f"solicitud={req.id}")
    return RedirectResponse(f"/casos/{req.case_id}", status_code=303)


@router.post("/solicitudes/{req_id}/estado")
def request_status(
    req_id: int,
    request: Request,
    status: str = Form(..., pattern="^(pendiente|recibido|cancelado)$"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    req = db.get(DocumentRequest, req_id)
    if req is None:
        raise HTTPException(status_code=404)
    req.status = status
    if status != "pendiente":
        req.token_hash = None  # invalida el enlace del cliente
    db.commit()
    audit(db, request, user.id, "solicitud_estado", f"solicitud={req.id} estado={status}")
    flash(request, "Solicitud actualizada.")
    return RedirectResponse(f"/casos/{req.case_id}", status_code=303)


@router.get("/documentos/{doc_id}/descargar")
def document_download(doc_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    if doc is None:
        raise HTTPException(status_code=404)
    data = load_decrypted(doc.stored_name)
    audit(db, request, user.id, "documento_descargado", f"documento={doc.id}")
    ascii_name = doc.original_name.encode("ascii", "ignore").decode() or "documento"
    ascii_name = ascii_name.replace('"', "")
    return Response(
        content=data,
        media_type=doc.content_type,
        headers={
            "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(doc.original_name)}"
        },
    )
