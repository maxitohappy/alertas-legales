FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts ./scripts

# Se ejecuta con un usuario sin privilegios
RUN useradd --create-home --uid 10001 appuser && mkdir -p /app/data && chown -R appuser /app/data
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*' --no-server-header"]
