# Alertas Legales — contexto para Claude

Sistema para un despacho de abogados en **España** que revisa los casos cada día, envía alertas de
plazos al despacho y pide/recuerda documentos a los clientes. Idioma del proyecto y de la UI: español.

## Arquitectura en producción
- **Panel web**: FastAPI + Jinja2 en **Render** (plan gratuito, Frankfurt) → https://alertas-legales.onrender.com
- **Base de datos**: PostgreSQL en **Neon** (Frankfurt). Migraciones con Alembic (se aplican al arrancar Render y en los workflows).
- **Documentos**: **Supabase Storage** (S3 compatible, path-style), cifrados con Fernet antes de guardarse.
- **Correo**: Gmail SMTP con contraseña de aplicación. **Render gratis bloquea SMTP**, así que el panel
  NUNCA envía correo: deja en cola (`DocumentRequest.send_now`, `received_notified`) y lo envía GitHub Actions.
- **GitHub Actions**:
  - `daily-check.yml`: revisión diaria 06:00 UTC (alertas de plazos, recordatorios, cola).
  - `envios-pendientes.yml`: cola cada 15 min (06-20 UTC) + disparo inmediato desde el panel
    (`app/dispatch.py`, token fine-grained `GITHUB_DISPATCH_TOKEN` en Render, permiso solo Actions).
  - `ci.yml` (ruff, pytest, bandit, pip-audit) y `codeql.yml`.
- Repo **público**: nada de datos personales en logs de Actions (los correos se enmascaran con `mask_email`).

## Decisiones tomadas
- Días de aviso configurables por plazo; si el aviso cae en inhábil se adelanta (festivos ES, `HOLIDAYS_SUBDIV=MD`).
- Idempotencia por tabla `notifications`; avisos atrasados se recuperan al día siguiente.
- 2FA TOTP obligatorio, Argon2id, CSRF, CSP, rate limiting, auditoría. Ver `docs/seguridad.md`.
- Los documentos recibidos se **adjuntan** al aviso del despacho (máx. 18 MB; `ATTACH_RECEIVED_DOCUMENTS`).
- Secretos solo en `.env` / `.env.produccion` (ignorados por git), GitHub Secrets y Render. Nunca pedir
  al usuario que pegue claves en el chat: usar `gh secret set NOMBRE` (entrada oculta).

## Comandos
- Tests y calidad: `.venv\Scripts\python -m pytest -q`, `ruff check .`, `ruff format .`, `bandit -r app scripts -c pyproject.toml`
- Simular revisión: `python -m app.jobs.daily_check --date 2026-12-04 --dry-run`
- Crear admin / renombrar en producción: `python -m scripts.create_admin <email> "<Nombre>" --produccion`,
  `python -m scripts.rename_user <email> "<Nombre>" --produccion`
- Lanzar workflows: `gh workflow run envios-pendientes.yml` / `gh workflow run daily-check.yml -f dry_run=true`
- Commits con identidad noreply local del repo; el usuario usa Windows (PowerShell en la terminal de VS Code).

## Pendientes (actualizar al avanzar)
- [ ] El usuario debe cargar en GitHub Secrets `S3_BUCKET`, `S3_ENDPOINT_URL`, `S3_REGION`, `S3_ACCESS_KEY`,
      `S3_SECRET_KEY` para que los avisos lleven los documentos adjuntos.
- [ ] Revisar/fusionar PRs de Dependabot (#1 setup-python, #2 checkout).
- [ ] Renovar el token `GITHUB_DISPATCH_TOKEN` antes de su caducidad (1 año) y rotar secretos anualmente.
- [ ] Cambiar `FIRM_NAME` por el nombre real del despacho (GitHub Secret + Render).
- Ideas futuras: dominio propio + Google Workspace (SPF/DKIM/DMARC), Render Starter, Supabase Pro,
  permisos por caso, integración calendario/LexNET.
- Página explicativa de la arquitectura para presentaciones: https://claude.ai/artifact/RqurW2oupK8Heq5y2Z2gM5
