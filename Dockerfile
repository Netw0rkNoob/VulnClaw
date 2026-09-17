# syntax=docker/dockerfile:1

# ── Stage 1: build the React Web UI ───────────────────────────────────
FROM node:20-bookworm-slim AS frontend
WORKDIR /frontend

# Install deps first for better layer caching
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Build the SPA into /frontend/dist
COPY frontend/ ./
RUN npm run build


# ── Stage 2: Python runtime ───────────────────────────────────────────
FROM python:3.12-slim-bookworm AS runtime

# Runtime tooling:
#   - nodejs/npm  → provides `npx` for npx-based MCP servers (e.g. memory)
#   - uv          → provides `uvx` for uvx-based MCP servers (e.g. fetch)
#   - git/curl    → commonly needed by MCP servers fetched on demand
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs \
        npm \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv/uvx for Python-based MCP servers (kept in a stable location on PATH)
RUN pip install --no-cache-dir uv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    # Persist config, sessions, targets, reports here (mount a volume)
    VULNCLAW_CONFIG_DIR=/data

WORKDIR /app

# Install Python deps first (better caching): copy only project metadata
COPY pyproject.toml README.md LICENSE ./
COPY vulnclaw ./vulnclaw
# pyproject.toml force-includes protocol/tui-v1.schema.json into the wheel;
# hatchling aborts the editable install when it is missing from the build root.
COPY protocol ./protocol

# Editable install so vulnclaw resolves to /app and finds frontend/dist.
#   web → fastapi + uvicorn for the Web UI
#   kb  → chromadb, so the knowledge base runs semantic search instead of
#         silently degrading to the keyword fallback
#   pdf → reportlab, so `vulnclaw report --pdf` works in the container
# `traffic` (mitmproxy + playwright) is deliberately excluded: Playwright also
# needs browser binaries pulled in via `playwright install`, which would add
# hundreds of MB. Add it here if you need the live proxy/browser backends.
RUN pip install -e ".[web,kb,pdf]"

# Bring in the built frontend so the full React UI is served (not the
# bundled single-file fallback). resolve_web_index() looks for this path.
COPY --from=frontend /frontend/dist ./frontend/dist

# Run as an unprivileged user; /data holds all mutable state.
RUN useradd --create-home --uid 1000 vulnclaw \
    && mkdir -p /data \
    && chown -R vulnclaw:vulnclaw /app /data
USER vulnclaw

VOLUME ["/data"]
EXPOSE 7788

# Default: launch the Web UI bound to all interfaces inside the container.
# (Binding to 0.0.0.0 is required for the published port to be reachable;
#  the host-side port mapping controls real exposure.)
ENTRYPOINT ["vulnclaw"]
CMD ["web", "--host", "0.0.0.0", "--port", "7788", "--allow-remote"]
