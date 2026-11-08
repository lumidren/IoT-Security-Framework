"""``python -m ironmesh_ota`` - run the service with uvicorn.

TLS for the public API is terminated by the ingress / ALB (deploy/helm); ``OTA_TLS_*`` are the
client credentials this service presents to the PKI, registry and EMQX.
"""

from __future__ import annotations

import sys

import uvicorn

from .app import create_app
from .runtime import build_container
from .settings import Settings


def main() -> int:
    settings = Settings()
    app = create_app(build_container(settings))
    uvicorn.run(
        app,
        host=settings.listen_host,
        port=settings.listen_port,
        log_config=None,
        proxy_headers=True,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
