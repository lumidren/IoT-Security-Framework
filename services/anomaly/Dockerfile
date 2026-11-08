# syntax=docker/dockerfile:1.7
# Build context: the repository root (the service depends on libs/python/ironmesh-wire):
#   docker build -f services/anomaly/Dockerfile -t ironmesh-anomaly .
ARG PYTHON_IMAGE=python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY libs/python/ironmesh-wire /src/libs/python/ironmesh-wire
COPY services/anomaly/pyproject.toml services/anomaly/README.md /src/services/anomaly/
COPY services/anomaly/src /src/services/anomaly/src
RUN pip install --upgrade pip \
 && pip install /src/libs/python/ironmesh-wire \
 && pip install /src/services/anomaly \
 && pip uninstall -y pip setuptools wheel \
 && find /opt/venv -name '__pycache__' -prune -exec rm -rf {} +

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="ironmesh-anomaly" \
      org.opencontainers.image.description="IronMesh runtime anomaly and threat detection" \
      org.opencontainers.image.source="https://github.com/lumidren/IoT-Security-Framework"
RUN groupadd --system --gid 10001 ironmesh \
 && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin ironmesh \
 && mkdir -p /var/lib/ironmesh/anomaly/models \
 && chown -R 10001:10001 /var/lib/ironmesh \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANOMALY_LISTEN_PORT=8002 \
    ANOMALY_MODEL_DIR=/var/lib/ironmesh/anomaly/models
USER 10001:10001
WORKDIR /var/lib/ironmesh/anomaly
EXPOSE 8002
VOLUME ["/var/lib/ironmesh/anomaly"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8002/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "ironmesh_anomaly"]
