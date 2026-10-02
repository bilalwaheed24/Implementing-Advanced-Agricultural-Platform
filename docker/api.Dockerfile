# syntax=docker/dockerfile:1
# `api` service (ADR-016): FastAPI backend only. No TensorFlow, no ledger, no frontend —
# those are the `ai`, `ledger` and `frontend` images. Non-root, read-only root filesystem.

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS base
ARG DEBIAN_FRONTEND=noninteractive

FROM base AS builder
WORKDIR /build
COPY requirements/api.txt requirements.txt
RUN pip install --no-cache-dir --user -r requirements.txt

FROM base AS runtime
LABEL org.opencontainers.image.title="ABSP api" \
      org.opencontainers.image.description="Agricultural Biotechnology Security Platform — REST API" \
      org.opencontainers.image.licenses="MIT"

# Debian security updates first: the base image lags the archive, and the CI Trivy gate
# fails on any fixable CRITICAL/HIGH finding.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 absp && useradd --uid 10001 --gid absp --no-create-home \
    --shell /usr/sbin/nologin absp

WORKDIR /app
COPY --from=builder /root/.local /home/absp/.local
# Packages were installed with `pip install --user` as root; PYTHONPATH makes them
# visible to the non-root runtime user whose $HOME differs.
ENV PATH=/home/absp/.local/bin:$PATH \
    PYTHONPATH=/home/absp/.local/lib/python3.12/site-packages \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENV=production

COPY backend/app/ backend/app/
COPY backend/migrations/ backend/migrations/
# Only the synthetic data generator from ai/ (demo seed, simulated crop images).
# Inference runs in the `ai` container.
COPY ai/__init__.py ai/__init__.py
COPY ai/data/ ai/data/
COPY scripts/start_api.py scripts/seed_demo.py scripts/
# The device simulator reuses this image (compose profile "simulator").
COPY iot/simulator.py iot/

RUN mkdir -p /app/data && chown -R absp:absp /app/data

USER absp
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3)" || exit 1

ENTRYPOINT ["python", "scripts/start_api.py"]
