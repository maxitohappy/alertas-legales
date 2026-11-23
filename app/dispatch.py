"""Aviso inmediato a GitHub Actions para que envíe los correos en cola.

Render (plan gratuito) bloquea el SMTP saliente, así que el panel no envía correo: pide a GitHub
que ejecute el workflow "Envíos pendientes del panel" en ese momento. Si el aviso falla, la
ejecución programada cada 15 minutos hace de respaldo.

El token debe ser un *fine-grained token* limitado a este repositorio con el permiso
"Actions: Read and write" y nada más.
"""

import json
import logging
import urllib.error
import urllib.request

from app.config import get_settings

log = logging.getLogger(__name__)
WORKFLOW_FILE = "envios-pendientes.yml"


def dispatch_enabled() -> bool:
    s = get_settings()
    return bool(s.github_dispatch_token and s.github_repo)


def trigger_queue_send() -> bool:
    """Lanza el workflow de envíos. Nunca lanza excepciones: devuelve True si GitHub lo aceptó."""
    s = get_settings()
    if not dispatch_enabled():
        return False
    url = f"https://api.github.com/repos/{s.github_repo}/actions/workflows/{WORKFLOW_FILE}/dispatches"
    request = urllib.request.Request(
        url,
        data=json.dumps({"ref": "main"}).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {s.github_dispatch_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "alertas-legales",
        },
    )
    try:
        # URL fija https://api.github.com (no controlada por usuarios)
        with urllib.request.urlopen(request, timeout=10) as resp:  # nosec B310  # noqa: S310
            return resp.status == 204
    except urllib.error.HTTPError as exc:
        log.warning("GitHub rechazó el aviso de envío (HTTP %s)", exc.code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log.warning("No se pudo avisar a GitHub: %s", type(exc).__name__)
    return False
