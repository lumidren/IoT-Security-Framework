"""Per-type downlink replay streams.

Revision ID: 0002_downlink_sequences
Revises: 0001_initial
Create Date: 2026-11-09

WIRE_FORMAT.md §3.6 step 11: a device keeps one replay counter per downlink stream
``"<tenant kid>/<type>"``. The registry is the only signer of tenant downlinks (ShadowDesired 4,
Command 5, OtaNotify 7, Config 9), so it allocates ``seq`` per (device, type) here. A stream
starts above the legacy per-device counter ``devices.downlink_seq`` (used for 4/5/9 before this
revision), so no device ever sees a sequence number go backwards.
"""

from __future__ import annotations

from alembic import op

revision = "0002_downlink_sequences"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE downlink_sequences (
            device_id  text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            msg_type   smallint NOT NULL CHECK (msg_type IN (4, 5, 7, 9)),
            tenant_id  uuid NOT NULL,
            last_seq   bigint NOT NULL CHECK (last_seq > 0),
            PRIMARY KEY (device_id, msg_type)
        )
        """
    )
    op.execute("CREATE INDEX downlink_sequences_tenant_idx ON downlink_sequences (tenant_id)")
    op.execute("ALTER TABLE downlink_sequences ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE downlink_sequences FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON downlink_sequences TO registry_app "
        "USING (tenant_id = current_setting('ironmesh.tenant_id')::uuid) "
        "WITH CHECK (tenant_id = current_setting('ironmesh.tenant_id')::uuid)"
    )
    op.execute(
        "DO $$ BEGIN EXECUTE format("
        "'CREATE POLICY owner_maintenance ON downlink_sequences TO %I USING (true) "
        "WITH CHECK (true)', current_user); END $$;"
    )
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON downlink_sequences TO registry_app")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS downlink_sequences CASCADE")
