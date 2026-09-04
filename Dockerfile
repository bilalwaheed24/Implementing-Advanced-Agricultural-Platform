# Multi-stage build. Non-root runtime, pinned base digest, minimal final layer.
# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS base
ARG DEBIAN_FRONTEND=noninteractive

FROM base AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM base AS runtime
LABEL org.opencontainers.image.title="Agricultural Biotechnology Security Platform" \
      org.opencontainers.image.description="Precision farming protection, GMO traceability, food supply chain security" \
      org.opencontainers.image.licenses="MIT"

# Non-root user (Security.md §15): fixed uid/gid, no login shell, no home directory writes needed.
RUN groupadd --gid 10001 absp && useradd --uid 10001 --gid absp --no-create-home \
    --shell /usr/sbin/nologin absp

WORKDIR /app
COPY --from=builder /root/.local /home/absp/.local
ENV PATH=/home/absp/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENV=production
# Packages were installed with `pip install --user` into /home/absp/.local. Python's
# user-site lookup is keyed to $HOME of the *running* user, and this stage's build steps
# run as root before USER absp is set below — root's HOME is /root, so it would never find
# them there. PYTHONPATH makes the location explicit regardless of which UID is running.
ENV PYTHONPATH=/home/absp/.local/lib/python3.12/site-packages

COPY backend/ backend/
COPY ai/ ai/
COPY ledger/ ledger/
COPY frontend/ frontend/
COPY scripts/ scripts/

# Train AI models at build time: the runtime container is read-only, so models must
# already exist in the image rather than be trained on first start. Uses only the
# synthetic generators in ai/data/generate.py (ADR-013) — no external data, no network.
# The full training path is used deliberately: --fast undertrains the crop-vision CNN
# and it confuses LEAF_BLIGHT with RUST, so the image would ship a model that misreads
# a live demonstration. It costs a few minutes of build time once.
RUN python3 scripts/train_models.py

# /app/data is the one writable path (a volume in both compose and Kubernetes); create
# it now and own it, since a fresh named volume otherwise mounts as root and a non-root
# container cannot write to it.
RUN mkdir -p /app/data/ledger \
    && chown -R absp:absp /app /app/data

USER absp
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--app-dir", "backend", "--proxy-headers"]
