"""Tenant policy owned by the registry and published to the PKI (API_CONTRACT §5).

The registry owns two fields of the PKI's per-tenant policy: the tenant **command key** (the
Ed25519 public key EST bundles carry so devices can verify downlinks) and the enrollment flag
``allow_software_keys``. Both are pushed together, idempotently, with ``PUT`` calls:

* when a command key is created (an outbox action queued in the key's own transaction),
* when ``allow_software_keys`` changes (``PATCH /v1/tenants/me/settings``),
* at startup for every tenant (reconciliation, which also creates missing command keys so a
  device never enrolls with a bundle that lacks one).

A failed push is retried with backoff; if it still fails an outbox action
(``pki_tenant_policy``) is stored and retried by the sweeper, so a PKI outage delays the update
but never loses it. Each push reads the current state, so a late retry cannot apply stale data.
A future command-key rotation must call :func:`sync` after committing the new key.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import structlog
from cryptography.hazmat.primitives import serialization

from ..auth import Principal
from ..context import AppContext
from ..crypto import PKI_TENANT_POLICY
from ..domain import ActionRecord
from ..problems import not_found

log = structlog.get_logger("app.tenant_policy")


async def push(app: AppContext, p: Principal, tenant_id: str) -> None:
    """Push the tenant's current command key and enrollment policy to the PKI (raises)."""
    async with app.unit(p, tenant_id) as u:
        tenant = await u.tx.get_tenant()
        if tenant is None:
            raise not_found("tenant")
        keys = await app.keyring.keys(u.tx)
    public_key = keys.cmd_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    await app.pki.put_command_key(tenant_id, public_key)
    await app.pki.put_enrollment(tenant_id, bool(tenant.settings.get("allow_software_keys")))


async def sync(app: AppContext, p: Principal, tenant_id: str, cause: str) -> bool:
    """:func:`push` with retries; on final failure store an outbox action. True if pushed."""
    try:
        await app.retry(PKI_TENANT_POLICY, lambda: push(app, p, tenant_id))
    except Exception as exc:
        async with app.unit(p, tenant_id) as u:
            now = u.now()
            action = ActionRecord(
                tenant_id=tenant_id,
                id=str(uuid.uuid4()),
                kind=PKI_TENANT_POLICY,
                device_id="",
                payload={"cause": cause},
                created_at=now,
                next_attempt_at=now + timedelta(seconds=30),
                attempts=app.settings.orchestration_attempts,
                last_error=str(exc),
            )
            await u.tx.insert_action(action)
            await u.audit(
                "tenant.pki_policy_sync_failed",
                "tenant",
                tenant_id,
                {
                    "cause": cause,
                    "error": str(exc),
                    "compensation": "retry_scheduled",
                    "action_id": action.id,
                },
                outcome="failure",
            )
        return False
    log.info("pki_tenant_policy_pushed", tenant_id=tenant_id, cause=cause)
    return True


async def reconcile(app: AppContext, p: Principal) -> int:
    """Startup reconciliation: push every tenant's current policy; returns how many succeeded."""
    done = 0
    for tenant_id in await app.repo.list_tenant_ids():
        try:
            if await sync(app, p, tenant_id, "startup_reconciliation"):
                done += 1
        except Exception as exc:  # one broken tenant must not stop the others
            log.error("pki_tenant_policy_reconcile_failed", tenant_id=tenant_id, error=repr(exc))
    return done
