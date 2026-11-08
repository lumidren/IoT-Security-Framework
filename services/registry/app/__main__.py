"""``python -m app``: run the registry with uvicorn (the container uses the CLI equivalent)."""

from __future__ import annotations

import uvicorn

from .settings import get_settings

if __name__ == "__main__":
    s = get_settings()
    uvicorn.run(
        "app.main:create_app",
        factory=True,
        host=s.listen_host,
        port=s.listen_port,
        proxy_headers=True,
        ws_max_size=65536,
        server_header=False,
    )
