# Alertas Legales ⚖️

Sistema para despachos de abogados que **revisa los casos todos los días de forma automática** y:

1. **Avisa al despacho por correo** de los plazos que se acercan (con la anticipación que se defina en
   cada plazo), de los que vencen hoy y de los vencidos.
2. **Pide automáticamente al cliente los documentos pendientes**, con un enlace seguro y personal para
   subirlos, y le recuerda cada N días hasta recibirlos. Cuando el cliente los sube, se avisa al despacho.

> Ejemplo: el caso de Juan Pérez tiene "Presentar recurso de libertad" el **05.12.2026** con aviso
> 1 día antes → el **04.12.2026** por la mañana el despacho recibe el correo de alerta, sin que ningún
> abogado tenga que revisar nada.

## Cómo funciona

```
Abogados ──HTTPS──► Panel web (FastAPI) ──► PostgreSQL (Neon, UE)
Clientes ──enlace seguro──► /subir/<token> ──► Almacenamiento cifrado (S3 / R2)
GitHub Actions (cada día 06:00 UTC) ──► python -m app.jobs.daily_check ──► Gmail ──► correos
```

- **Días hábiles de España:** si el día de aviso cae en fin de semana o festivo (nacional y de la
  comunidad autónoma configurada) el aviso se **adelanta** al día hábil anterior. El panel advierte si
  una fecha límite cae en día inhábil.
- **Sin duplicados y sin pérdidas:** cada envío queda registrado; si el proceso se ejecuta dos veces no
  repite correos, y si un día no se ejecuta, el aviso se envía al día siguiente.
- **Un correo resumen por destinatario** (abogado responsable del caso + correos del despacho).

## Seguridad

2FA obligatorio, Argon2id, cifrado de documentos en reposo, CSRF, CSP, rate limiting, bloqueo de
cuentas, enlaces de un solo uso, auditoría, CodeQL, bandit, pip-audit y Dependabot.
Análisis completo de amenazas, controles y cumplimiento RGPD/LOPDGDD: **[docs/seguridad.md](docs/seguridad.md)**.

## Puesta en marcha local

Requisitos: Python 3.12 o superior.

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt -r requirements-dev.txt
copy .env.example .env            # y complete SECRET_KEY, ENCRYPTION_KEY, correos...
alembic upgrade head
python -m scripts.create_admin admin@despacho.es "Nombre Apellido"
python -m scripts.seed_demo       # opcional: caso demo de Juan Pérez (usa DEMO_EMAIL)
uvicorn app.main:app --reload     # http://localhost:8000
```

Simular la revisión diaria de una fecha concreta sin enviar nada:

```bash
python -m app.jobs.daily_check --date 2026-12-04 --dry-run
```

Enviar de verdad (requiere `SMTP_USER` y `SMTP_PASSWORD` en `.env`):

```bash
python -m app.jobs.daily_check --date 2026-12-04
```

Tests y análisis: `pytest`, `ruff check .`, `bandit -r app -c pyproject.toml`, `pip-audit -r requirements.txt`.

### Contraseña de aplicación de Gmail

1. Active la verificación en dos pasos en la cuenta de Google que enviará los correos.
2. Vaya a <https://myaccount.google.com/apppasswords> y cree una contraseña de aplicación.
3. Póngala en `SMTP_PASSWORD` (en `.env` o en los *secrets*), nunca en el código.

## Despliegue en producción

1. **Base de datos:** cree un proyecto en [Neon](https://neon.tech) en región UE (Frankfurt) y copie la
   cadena de conexión (`postgresql://...?sslmode=require`).
2. **Almacenamiento:** cree un bucket **privado** en [Supabase Storage](https://supabase.com) (gratis,
   sin tarjeta, región UE), Cloudflare R2 o AWS S3, y unas credenciales S3 con acceso a ese bucket.
   En Supabase: *Project Settings → Storage → S3 Connection* (endpoint, región y *New access key*).
3. **App web:** en [Render](https://render.com) → *New → Blueprint* → este repositorio (usa
   `render.yaml`: plan gratuito, región Frankfurt). Complete las variables secretas. Las migraciones
   se aplican solas.
4. **Administrador:** el plan gratuito de Render no tiene consola, así que se crea desde su PC
   apuntando a la base de datos de producción (PowerShell):
   ```
   python -m scripts.create_admin admin@despacho.es "Nombre Apellido" --produccion
   ```
   El script pide la cadena de conexión de Neon de forma oculta (no queda en el historial).
5. **Revisión diaria:** en GitHub → *Settings → Secrets and variables → Actions*, cree los secrets:
   `DATABASE_URL`, `SECRET_KEY`, `ENCRYPTION_KEY` (los **mismos** que en Render), `APP_BASE_URL`,
   `FIRM_NAME`, `FIRM_ALERT_EMAILS`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM`; y la variable
   `HOLIDAYS_SUBDIV` (p. ej. `MD`). El workflow **Revisión diaria de casos** se ejecuta cada mañana y
   también puede lanzarse a mano (*Run workflow*), con fecha y modo simulación opcionales.

> GitHub desactiva los workflows programados de repositorios públicos sin actividad durante 60 días;
> si ocurre, reactívelo desde la pestaña *Actions* (GitHub avisa por correo antes de hacerlo).

## Estructura

```
app/
  alerts.py          lógica pura de alertas (qué toca enviar hoy)
  business_days.py   calendario laboral de España
  notifier.py        revisión diaria: resúmenes al despacho y solicitudes a clientes
  jobs/daily_check.py  comando ejecutado por GitHub Actions
  routers/           panel web, login 2FA, portal de carga del cliente
  security.py        Argon2, 2FA, CSRF, tokens, rate limiting, cifrado
  storage.py         validación y almacenamiento cifrado de archivos
alembic/             migraciones de la base de datos
tests/               tests automatizados (alertas, proceso diario, seguridad web)
docs/seguridad.md    análisis de seguridad
```
