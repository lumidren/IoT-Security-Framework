"""Leader election for the rollout controller.

:class:`PostgresAdvisoryLock` holds a session-level ``pg_try_advisory_lock`` on a dedicated
connection. Postgres releases the lock when that session ends, so a crashed or partitioned
replica loses leadership automatically; the holder re-validates its connection on every tick and
steps down if the check fails.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine


class LeaderLock(Protocol):
    async def acquire(self) -> bool:
        """Try to become (or confirm still being) the leader; never blocks."""

    async def release(self) -> None: ...


@dataclass
class FakeLockServer:
    """Shared state for :class:`FakeLeaderLock` instances (models one Postgres server)."""

    holder: str | None = None
    healthy: dict[str, bool] = field(default_factory=dict)


class FakeLeaderLock:
    def __init__(self, server: FakeLockServer, name: str) -> None:
        self.server = server
        self.name = name
        server.healthy.setdefault(name, True)

    async def acquire(self) -> bool:
        if not self.server.healthy.get(self.name, True):
            # this replica's session died: the server drops the lock it held
            if self.server.holder == self.name:
                self.server.holder = None
            return False
        if self.server.holder in (None, self.name):
            self.server.holder = self.name
            return True
        return False

    async def release(self) -> None:
        if self.server.holder == self.name:
            self.server.holder = None


class PostgresAdvisoryLock:
    def __init__(self, engine: AsyncEngine, key: int) -> None:
        self._engine = engine
        self._key = key
        self._conn: AsyncConnection | None = None

    async def acquire(self) -> bool:
        if self._conn is not None:
            try:
                held = (
                    await self._conn.execute(
                        text(
                            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                            "AND pid = pg_backend_pid() AND objid = :k AND granted"
                        ),
                        {"k": self._key & 0xFFFFFFFF},
                    )
                ).scalar()
                if held:
                    return True
            except Exception:
                await self._drop()
                return False
        if self._conn is None:
            self._conn = await self._engine.connect()
            await self._conn.execution_options(isolation_level="AUTOCOMMIT")
        try:
            got = (
                await self._conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": self._key})
            ).scalar()
        except Exception:
            await self._drop()
            return False
        if not got:
            await self._drop()
        return bool(got)

    async def _drop(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                await conn.invalidate()
            finally:
                await conn.close()

    async def release(self) -> None:
        if self._conn is None:
            return
        try:
            await self._conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": self._key})
        finally:
            await self._drop()
