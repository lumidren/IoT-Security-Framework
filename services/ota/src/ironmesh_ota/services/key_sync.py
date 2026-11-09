"""Push the firmware signing public keys to the PKI tenant policy (API_CONTRACT §5).

The OTA service owns the ``firmware-keys`` field: EST bundles carry these keys so devices can
verify manifests. Every tenant with firmware (campaigns always reference firmware) is listed in
the ``pki_key_sync`` outbox, registered in the transaction that stores its first image. A tenant
is due whenever the digest of the key set the PKI last accepted differs from the current key
ring's, so a signing-key rotation (new ring, then restart) is pushed automatically; startup also
marks every tenant for a fresh push. Failures are retried after :data:`RETRY_S`.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

from ..container import Container
from ..observability import get_logger

log = get_logger("ironmesh.ota.key_sync")

RETRY_S = 60
BATCH = 100


class FirmwareKeySync:
    def __init__(self, container: Container) -> None:
        self.c = container

    def public_keys(self) -> list[bytes]:
        """Every trusted key (active and retired, Ed25519 and ML-DSA-65), so images signed
        before a rotation still verify on devices."""
        return sorted(self.c.signer.trusted_public_keys())

    def digest(self) -> str:
        h = hashlib.sha256()
        for key in self.public_keys():
            h.update(len(key).to_bytes(4, "big") + key)
        return h.hexdigest()

    async def request_all(self) -> int:
        """Startup: mark every registered tenant for a fresh push."""
        return await self.c.db.request_key_sync_all(self.c.clock())

    async def run_due(self) -> int:
        """Push to every due tenant; returns how many the PKI accepted."""
        digest, keys, done = self.digest(), self.public_keys(), 0
        now = self.c.clock()
        for tenant_id in await self.c.db.due_key_syncs(digest, now, BATCH):
            try:
                await self.c.pki.put_firmware_keys(tenant_id, keys)
            except Exception as exc:
                log.warning(
                    "pki firmware-keys push failed; will retry",
                    tenant_id=str(tenant_id),
                    error=str(exc),
                )
                await self.c.db.finish_key_sync(
                    tenant_id,
                    digest=digest,
                    now=now,
                    error=str(exc) or type(exc).__name__,
                    retry_at=now + timedelta(seconds=RETRY_S),
                )
                continue
            await self.c.db.finish_key_sync(tenant_id, digest=digest, now=now)
            log.info("pki firmware keys pushed", tenant_id=str(tenant_id), keys=len(keys))
            done += 1
        return done
