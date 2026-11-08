"""Entry point: ``python -m ironmesh_anomaly`` (or the ``ironmesh-anomaly`` script)."""

from __future__ import annotations

import asyncio

import uvicorn

from .app import build_components, create_app
from .config import Settings
from .observability import configure_logging, configure_tracing


def main() -> None:
    settings = Settings()
    configure_logging(settings.service_name, settings.log_level, settings.log_format)
    configure_tracing(settings.service_name, settings.otlp_endpoint)
    components = asyncio.run(build_components(settings))
    app = create_app(components)
    uvicorn.run(
        app,
        host=settings.listen_host,
        port=settings.listen_port,
        log_config=None,
        access_log=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
