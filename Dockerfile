# CodeAudit Agent — single-image demo/production build.
# Serves the API and the demo frontend (at /ui) from one container.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps: git (repo cloning), build tools for pinned wheels if needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
  && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY backend ./backend
COPY frontend ./frontend

# Run as a non-root user; the SQLite fallback DB lives in its home dir.
RUN useradd -m -u 10001 codeaudit \
  && mkdir -p /home/codeaudit/data \
  && chown -R codeaudit:codeaudit /app /home/codeaudit
USER codeaudit

# Production defaults: auth REQUIRED, SQLite only as a fallback.
# Override at deploy time (see docs/PRODUCTION.md).
ENV CODEAUDIT_REQUIRE_AUTH=true \
    CODEAUDIT_DATABASE_URL="" \
    PORT=8000

EXPOSE 8000

WORKDIR /app/backend
CMD ["sh", "-c", "python -m uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
