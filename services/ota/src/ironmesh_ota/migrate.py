"""Run the Alembic migrations programmatically (``python -m ironmesh_ota.migrate``).

The migration role must own the schema; the service itself connects as ``ota_app``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

MIGRATIONS = Path(__file__).parent / "migrations"


def alembic_config(url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    if url:
        cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def upgrade(url: str | None = None, revision: str = "head") -> None:
    command.upgrade(alembic_config(url), revision)


def downgrade(url: str | None = None, revision: str = "base") -> None:
    command.downgrade(alembic_config(url), revision)


def main() -> int:  # pragma: no cover - thin CLI
    upgrade(os.environ.get("OTA_MIGRATION_DATABASE_URL"))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
