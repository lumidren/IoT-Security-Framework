"""Alembic environment. The URL comes from ``OTA_MIGRATION_DATABASE_URL`` (an owner role, not
``ota_app``) or from the ``sqlalchemy.url`` option set programmatically by ``ironmesh_ota.migrate``.
"""

from __future__ import annotations

import asyncio
import os

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config
url = config.get_main_option("sqlalchemy.url") or os.environ.get("OTA_MIGRATION_DATABASE_URL")


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=None, transaction_per_migration=True)
    with context.begin_transaction():
        context.run_migrations()


async def _online() -> None:
    if not url:
        raise RuntimeError("set OTA_MIGRATION_DATABASE_URL")
    engine = create_async_engine(url)
    async with engine.connect() as conn:
        await conn.run_sync(_run)
        await conn.commit()
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=url, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_online())
