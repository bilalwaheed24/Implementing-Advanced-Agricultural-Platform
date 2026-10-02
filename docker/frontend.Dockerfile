# syntax=docker/dockerfile:1
# `frontend` service (ADR-016): nginx serving frontend/ and reverse-proxying the api.
# Unprivileged image (uid 101, port 8080); runs with a read-only root filesystem.
FROM nginxinc/nginx-unprivileged:stable-alpine@sha256:ed04ec1ff34502c339ee5c3ae3f855442398edc1d05591e2b98981dcbbd20b1e

LABEL org.opencontainers.image.title="ABSP frontend" \
      org.opencontainers.image.description="Agricultural Biotechnology Security Platform — web UI and reverse proxy" \
      org.opencontainers.image.licenses="MIT"

USER root
RUN apk upgrade --no-cache
USER 101

COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY docker/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY frontend/ /usr/share/nginx/html/

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
