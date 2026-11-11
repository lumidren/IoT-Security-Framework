# syntax=docker/dockerfile:1.7
# Build context: the repository root (the service depends on libs/python/ironmesh-wire):
#   docker build -f services/ota/Dockerfile -t ghcr.io/lumidren/ironmesh-ota:dev .
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY libs/python/ironmesh-wire/pyproject.toml libs/python/ironmesh-wire/README.md libs/wire/
COPY libs/python/ironmesh-wire/src libs/wire/src
COPY services/ota/pyproject.toml services/ota/README.md ota/
COPY services/ota/src ota/src
RUN pip install --upgrade pip \
 && pip install ./libs/wire ./ota \
 && python -m compileall -q /opt/venv/lib \
 && pip uninstall --yes pip setuptools wheel

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="ironmesh-ota" \
      org.opencontainers.image.source="https://github.com/lumidren/IoT-Security-Framework" \
      org.opencontainers.image.licenses="Apache-2.0"
# The service runs from /opt/venv and never installs packages at runtime. The base image's pip,
# setuptools and wheel are unused, and pip vendors an old setuptools pkg_resources that scanners
# report as CVE-2025-47273, so all three are removed (as in the anomaly image).
RUN python -m pip uninstall --yes pip setuptools wheel
RUN groupadd --system --gid 10001 ota \
 && useradd --system --uid 10001 --gid ota --home-dir /nonexistent --shell /usr/sbin/nologin ota \
 && mkdir -p /var/lib/ironmesh/ota/artifacts \
 && chown -R 10001:10001 /var/lib/ironmesh/ota
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OTA_LISTEN_PORT=8001 \
    OTA_ARTIFACT_PATH=/var/lib/ironmesh/ota/artifacts \
    TMPDIR=/tmp
USER 10001:10001
WORKDIR /var/lib/ironmesh/ota
EXPOSE 8001
VOLUME ["/var/lib/ironmesh/ota", "/tmp"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD ["python", "-c", "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('OTA_LISTEN_PORT','8001')+'/healthz',timeout=2)"]
ENTRYPOINT ["python", "-m", "ironmesh_ota"]
