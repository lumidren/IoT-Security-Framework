# syntax=docker/dockerfile:1.7
# Build from the repository root (the wire library lives outside this directory):
#   docker build -f services/registry/Dockerfile -t ironmesh-registry .

FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY libs/python/ironmesh-wire /src/libs/python/ironmesh-wire
RUN pip install /src/libs/python/ironmesh-wire
COPY services/registry/pyproject.toml services/registry/README.md /src/services/registry/
COPY services/registry/app /src/services/registry/app
RUN pip install /src/services/registry

FROM python:3.12-slim AS runtime
# Pick up Debian security updates released after the base image was built.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 ironmesh \
 && useradd --system --uid 10001 --gid ironmesh --no-create-home --shell /usr/sbin/nologin ironmesh
COPY --from=build /opt/venv /opt/venv
WORKDIR /srv
COPY services/registry/alembic.ini /srv/alembic.ini
COPY services/registry/migrations /srv/migrations
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REGISTRY_LISTEN_PORT=8000 \
    FORWARDED_ALLOW_IPS=127.0.0.1
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('REGISTRY_LISTEN_PORT','8000')}/healthz\",timeout=2)"]
# --proxy-headers trusts X-Forwarded-* only from FORWARDED_ALLOW_IPS (set it to the ingress/LB range).
CMD ["sh", "-c", "exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port ${REGISTRY_LISTEN_PORT} --proxy-headers --forwarded-allow-ips ${FORWARDED_ALLOW_IPS} --ws-max-size 65536 --no-server-header"]
