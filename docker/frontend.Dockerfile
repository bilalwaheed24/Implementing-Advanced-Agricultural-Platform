# syntax=docker/dockerfile:1
# `frontend` service (ADR-016): nginx serving frontend/ and reverse-proxying the api.
# Unprivileged image (uid 101, port 8080); runs with a read-only root filesystem.
FROM nginxinc/nginx-unprivileged:stable-alpine@sha256:f5116ed4606f3eb015dd4a8e28cb9b351476dc0ad4bc6e9f93b19cec130cdf03

LABEL org.opencontainers.image.title="ABSP frontend" \
      org.opencontainers.image.description="Agricultural Biotechnology Security Platform — web UI and reverse proxy" \
      org.opencontainers.image.licenses="MIT"

# Alpine security updates, for everything the base does not hold back. nginx itself is
# pinned to an exact version in the base image's /etc/apk/world (nginx=1.30.6-r1 and its
# modules), so apk cannot move it: a fixed nginx CVE is only picked up by refreshing the
# digest above. The CI Trivy gate fails on fixable HIGH/CRITICAL findings, so when it
# flags nginx, re-pin FROM to the current stable-alpine digest rather than relaxing it.
USER root
RUN apk upgrade --no-cache
USER 101

COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY docker/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY frontend/ /usr/share/nginx/html/

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
