# syntax=docker/dockerfile:1
# `ledger` service (ADR-016): the permissioned ledger node. Sole writer of /data/ledger.
# Internal only — not published.

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS base
ARG DEBIAN_FRONTEND=noninteractive

FROM base AS builder
WORKDIR /build
COPY requirements/ledger.txt requirements.txt
RUN pip install --no-cache-dir --user -r requirements.txt

FROM base AS runtime
LABEL org.opencontainers.image.title="ABSP ledger" \
      org.opencontainers.image.description="Agricultural Biotechnology Security Platform — permissioned ledger node (single-node ordering, DEMO)" \
      org.opencontainers.image.licenses="MIT"

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 absp && useradd --uid 10001 --gid absp --no-create-home \
    --shell /usr/sbin/nologin absp

WORKDIR /app
COPY --from=builder /root/.local /home/absp/.local
ENV PATH=/home/absp/.local/bin:$PATH \
    PYTHONPATH=/home/absp/.local/lib/python3.12/site-packages \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LEDGER_DATA_DIR=/data/ledger

COPY ledger/ ledger/

# A fresh named volume mounts with the image's ownership of this path.
RUN mkdir -p /data/ledger && chown -R absp:absp /data

USER absp
EXPOSE 8200

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8200/health', timeout=3)" || exit 1

CMD ["python", "-m", "uvicorn", "ledger.service:app", "--host", "0.0.0.0", "--port", "8200"]
