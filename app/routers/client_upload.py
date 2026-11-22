"""Página pública donde el cliente sube documentos mediante su enlace personal."""

import logging

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.deps import audit
from app.models import Document, DocumentRequest, as_aware, utcnow
from app.security import client_ip, hash_token, rate_limiter
from app.storage import MAX_FILES_PER_UPLOAD, UploadRejected, save_encrypted, validate_upload
from app.web import templates

router = APIRouter()
log = logging.getLogger(__name__)
INVALID_LINK = "Este enlace no es válido o ha caducado. Si aún debe enviar documentación, contacte con el despacho."


def _request_for_token(db: Session, token: str) -> DocumentRequest:
    if len(token) > 100:
        raise HTTPException(status_code=404, detail=INVALID_LINK)
    req = db.scalar(select(DocumentRequest).where(DocumentRequest.token_hash == hash_token(token)))
    expires = as_aware(req.token_expires_at) if req else None
    if req is None or req.status != "pendiente" or expires is None or expires < utcnow():
        raise HTTPException(status_code=404, detail=INVALID_LINK)
    return req


def _limit(request: Request) -> None:
    if not rate_limiter.allow(f"upload:{client_ip(request)}", 20, 600):
        raise HTTPException(status_code=429, detail="Demasiados intentos. Espere unos minutos.")


@router.get("/subir/{token}")
def upload_form(token: str, request: Request, db: Session = Depends(get_db)):
    _limit(request)
    req = _request_for_token(db, token)
    return templates.TemplateResponse(
        request,
        "upload.html",
        {"req": req, "error": None, "max_mb": get_settings().upload_max_mb, "max_files": MAX_FILES_PER_UPLOAD},
    )


@router.post("/subir/{token}")
async def upload(token: str, request: Request, files: list[UploadFile] = File(...), db: Session = Depends(get_db)):
    _limit(request)
    req = _request_for_token(db, token)
    ctx = {"req": req, "max_mb": get_settings().upload_max_mb, "max_files": MAX_FILES_PER_UPLOAD}
    files = [f for f in files if f.filename]
    if not files or len(files) > MAX_FILES_PER_UPLOAD:
        return templates.TemplateResponse(
            request,
            "upload.html",
            {**ctx, "error": f"Seleccione entre 1 y {MAX_FILES_PER_UPLOAD} archivos."},
            status_code=400,
        )
    max_bytes = get_settings().upload_max_mb * 1024 * 1024
    validated = []
    try:
        for f in files:
            data = await f.read(max_bytes + 1)
            validated.append(validate_upload(f.filename or "", data))
    except UploadRejected as exc:
        audit(db, request, None, "carga_rechazada", f"solicitud={req.id} motivo={exc}")
        return templates.TemplateResponse(request, "upload.html", {**ctx, "error": str(exc)}, status_code=400)

    for v in validated:
        db.add(
            Document(
                request_id=req.id,
                stored_name=save_encrypted(v.data),
                original_name=v.original_name,
                content_type=v.content_type,
                size=len(v.data),
                sha256=v.sha256,
            )
        )
    # Enlace de un solo uso: se invalida al recibir la documentación.
    req.status, req.received_at, req.token_hash = "recibido", utcnow(), None
    req.received_notified = False  # el aviso al despacho lo envía GitHub Actions
    db.commit()
    audit(db, request, None, "documento_recibido", f"solicitud={req.id} archivos={len(validated)}")

    return templates.TemplateResponse(request, "upload_ok.html", {"count": len(validated)})
