# Image for the API (and the one-shot CLI jobs, which share the same code).
FROM python:3.12-slim

# No .pyc clutter; logs appear immediately instead of sitting in a buffer.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first, code second. Docker caches each layer, so editing app
# code does not re-run the slow pip install -- only changing requirements does.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app
COPY scripts ./scripts

# Don't run as root: if the app is ever compromised, the attacker gets an
# unprivileged user rather than root inside the container.
RUN useradd --create-home --uid 1000 appuser && mkdir -p /app/reports && chown appuser /app/reports
USER appuser

EXPOSE 8000
# 0.0.0.0, not 127.0.0.1: inside a container, loopback is unreachable from
# the published port.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
