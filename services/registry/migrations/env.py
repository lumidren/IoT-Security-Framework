"""Alembic environment (async, asyncpg). Runs as the schema owner."""

from __future__ import annotations

import asyncio
import os

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config


def _url() -> str:
    url = config.attributes.get("url") or os.environ.get("REGISTRY_MIGRATION_DATABASE_URL")
    if not url:
        raise RuntimeError("set REGISTRY_MIGRATION_DATABASE_URL to the schema owner's DSN")
    return str(url)


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=None, transaction_per_migration=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run_async() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as connection:
        await connection.run_sync(_run)
        await connection.commit()
    await engine.dispose()


def run_migrations_offline() -> None:
    context.configure(url=_url(), literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(_run_async())
