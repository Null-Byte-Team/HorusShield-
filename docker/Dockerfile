# ══════════════════════════════════════════════════════════════════
# HorusShield 2.0 — Dockerfile
# Team NullByte · WE School · Alexandria 🇪🇬
# ══════════════════════════════════════════════════════════════════
# Runs the existing Flask/Socket.IO backend headlessly (HORUS_HEADLESS=true)
# and serves the same, unmodified HorusShield_UI.html — no UI changes.
#
# NOTE on network monitoring: HorusShield's packet capture (scapy) needs
# raw-socket access. In Docker that means running with
# `--cap-add=NET_ADMIN --cap-add=NET_RAW --network host` (already set in
# docker-compose.yml). Without those, the app still runs — network-capture
# features will just report no traffic, exactly like a permission-denied
# case on the desktop app.
#
# pywebview is intentionally NOT installed in this image — the container
# has no display for it to attach to, and app.py only imports it lazily
# when NOT running headless, so it's never needed here.

# ── Stage 1: build dependencies into a venv ──
FROM python:3.11-slim AS builder

WORKDIR /build

# libpcap-dev is needed to build/validate scapy's optional C extensions;
# build-essential covers any package without a prebuilt wheel for this arch.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /build/requirements.txt

# pywebview is excluded — it needs a GUI toolkit this headless image doesn't
# ship, and is never imported when HORUS_HEADLESS=true (see backend/app.py).
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && grep -v '^pywebview' /build/requirements.txt > /build/requirements-docker.txt \
    && /opt/venv/bin/pip install --no-cache-dir -r /build/requirements-docker.txt

# ── Stage 2: slim runtime image ──
FROM python:3.11-slim AS runtime

LABEL maintainer="Team NullByte — WE School, Alexandria"
LABEL description="HorusShield 2.0 — Egyptian AI Cybersecurity Platform (headless/server mode)"

# libpcap0.8 = runtime lib scapy needs to actually open sockets;
# curl = used by the container HEALTHCHECK below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 horus

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HORUS_HEADLESS=true \
    HORUS_HOST=0.0.0.0 \
    HORUS_PORT=5050 \
    HORUS_DB_PATH=/data/horus.db \
    HORUS_LOG_FILE=/data/logs/horus.log

WORKDIR /app

# Copy only what the running app needs — same files the desktop app uses.
COPY backend/ /app/backend/
COPY HorusShield_UI.html /app/HorusShield_UI.html

# Writable volume mount point for the database, logs, and generated reports —
# kept outside /app so it survives image rebuilds/updates.
RUN mkdir -p /data/logs /data/reports /app/backend/reports/vscans \
    && chown -R horus:horus /app /data

USER horus
WORKDIR /app/backend

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5050/api/health || exit 1

CMD ["python", "app.py"]
