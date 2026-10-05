# syntax=docker/dockerfile:1
# `ai` service (ADR-016): model inference over HTTP. Internal only — not published.

FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS base
ARG DEBIAN_FRONTEND=noninteractive

FROM base AS builder
WORKDIR /build
COPY requirements/ai.txt requirements.txt
RUN pip install --no-cache-dir --user -r requirements.txt

FROM base AS runtime
LABEL org.opencontainers.image.title="ABSP ai" \
      org.opencontainers.image.description="Agricultural Biotechnology Security Platform — AI inference service" \
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
    TF_CPP_MIN_LOG_LEVEL=2

COPY ai/ ai/
COPY scripts/train_models.py scripts/

# Train at build time: the container is read-only, so models must already be in the
# image. Synthetic data only (ADR-013), no network. The full path is deliberate — --fast
# undertrains the crop-vision CNN and it confuses LEAF_BLIGHT with RUST.
RUN python3 scripts/train_models.py

USER absp
EXPOSE 8100

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8100/health', timeout=3)" || exit 1

CMD ["python", "-m", "uvicorn", "ai.service:app", "--host", "0.0.0.0", "--port", "8100"]
