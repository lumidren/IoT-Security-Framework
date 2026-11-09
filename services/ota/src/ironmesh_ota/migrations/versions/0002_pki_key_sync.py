"""Firmware-key sync outbox for the PKI tenant policy (API_CONTRACT §5).

Revision ID: 0002_pki_key_sync
Revises: 0001_initial
Create Date: 2026-11-09

``pki_key_sync`` lists the tenants that have firmware (every campaign references firmware) and
the digest of the firmware public-key set the PKI last accepted for each. It is an
identifier-only table without RLS, like ``campaign_schedule``: the rollout controller reads it
across tenants to push ``PUT /v1/tenants/{t}/firmware-keys`` with retry and back-off.
Existing tenants are backfilled from ``firmware``.
"""

from __future__ import annotations

from alembic import op

revision = "0002_pki_key_sync"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE pki_key_sync (
            tenant_id uuid PRIMARY KEY,
            digest text,
            attempts integer NOT NULL DEFAULT 0,
            next_attempt_at timestamptz NOT NULL,
            last_error text,
            synced_at timestamptz
        )
        """
    )
    op.execute("CREATE INDEX ix_pki_key_sync_due ON pki_key_sync (next_attempt_at)")
    # FORCE RLS binds the table owner too; lift it for the backfill only (same transaction).
    op.execute("ALTER TABLE firmware NO FORCE ROW LEVEL SECURITY")
    op.execute(
        "INSERT INTO pki_key_sync (tenant_id, next_attempt_at) "
        "SELECT DISTINCT tenant_id, now() FROM firmware ON CONFLICT DO NOTHING"
    )
    op.execute("ALTER TABLE firmware FORCE ROW LEVEL SECURITY")
    op.execute("GRANT SELECT, INSERT, UPDATE ON pki_key_sync TO ota_app")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS pki_key_sync")
