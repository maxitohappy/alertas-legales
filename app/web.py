"""Plantillas Jinja2 (autoescape activado) compartidas por panel y correos."""

from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.config import get_settings
from app.security import csrf_token

TEMPLATES_DIR = Path(__file__).parent / "templates"


def fmt_date(value: date | datetime | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, datetime):
        return value.astimezone(ZoneInfo(get_settings().timezone)).strftime("%d.%m.%Y %H:%M")
    return value.strftime("%d.%m.%Y")


def local_today() -> date:
    return datetime.now(ZoneInfo(get_settings().timezone)).date()


def local_date(value: datetime | None) -> date | None:
    if value is None:
        return None
    from app.models import as_aware

    return as_aware(value).astimezone(ZoneInfo(get_settings().timezone)).date()


def flash(request, message: str, kind: str = "ok") -> None:
    request.session.setdefault("flash", []).append([kind, message])


def pop_flashes(request) -> list:
    return request.session.pop("flash", [])


templates = Jinja2Templates(directory=str(TEMPLATES_DIR / "panel"))
templates.env.globals["pop_flashes"] = pop_flashes
templates.env.filters["fecha"] = fmt_date
templates.env.globals["csrf_token"] = csrf_token
templates.env.globals["firm_name"] = lambda: get_settings().firm_name

_email_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR / "email")),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_email_env.filters["fecha"] = fmt_date


def render_email(name: str, **ctx) -> tuple[str, str]:
    """Devuelve (texto_plano, html) a partir de <name>.txt y <name>.html."""
    s = get_settings()
    ctx.setdefault("firm_name", s.firm_name)
    ctx.setdefault("base_url", s.app_base_url.rstrip("/"))
    return _email_env.get_template(f"{name}.txt").render(**ctx), _email_env.get_template(f"{name}.html").render(**ctx)
