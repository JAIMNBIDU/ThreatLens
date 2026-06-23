# ── ThreatLens backend ────────────────────────────────────────────────────────
# Pinned interpreter (3.12 = widest wheel coverage) so the pydantic/Python-3.13
# source-build failure can never recur on a teammate's or server's machine.
FROM python:3.12-slim

# No .pyc writes, unbuffered logs, no pip cache bloating the layer.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching. Wheels only — no compiler in the image.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# App code (NOT .env, NOT the db — see .dockerignore).
COPY . .

# Run as a non-root user; give it the writable data dir for SQLite.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data && chown -R appuser:appuser /data /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).status==200 else 1)"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
