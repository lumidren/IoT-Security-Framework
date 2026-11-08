"""Initial OTA schema with row-level security.

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-09
"""

from __future__ import annotations

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "firmware",
    "firmware_deltas",
    "campaigns",
    "campaign_devices",
    "audit_events",
    "idempotency_keys",
    "device_seq",
)

TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('ironmesh.tenant_id', true), '')::uuid"

DDL = """
CREATE TABLE firmware (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    product text NOT NULL CHECK (product ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    version text NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    version_code bigint NOT NULL CHECK (version_code >= 1),
    sha256 bytea NOT NULL CHECK (length(sha256) = 32),
    size bigint NOT NULL CHECK (size >= 0),
    min_version_code bigint NOT NULL CHECK (min_version_code >= 0 AND min_version_code <= version_code),
    created_at timestamptz NOT NULL,
    created_by text,
    manifest bytea NOT NULL,
    signed_manifest bytea NOT NULL,
    signing_key_id text NOT NULL,
    pq_signed boolean NOT NULL,
    notes text,
    severity text NOT NULL CHECK (severity IN ('normal', 'security')),
    image_key text NOT NULL,
    manifest_key text NOT NULL,
    signature_key text NOT NULL,
    rollback_of uuid REFERENCES firmware (id),
    CONSTRAINT uq_firmware_version UNIQUE (tenant_id, product, version),
    CONSTRAINT uq_firmware_version_code UNIQUE (tenant_id, product, version_code)
);
CREATE INDEX ix_firmware_sha256 ON firmware (tenant_id, sha256);
CREATE INDEX ix_firmware_created ON firmware (tenant_id, created_at, id);

CREATE TABLE firmware_deltas (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    firmware_id uuid NOT NULL REFERENCES firmware (id),
    base_sha256 bytea NOT NULL CHECK (length(base_sha256) = 32),
    patch_sha256 bytea NOT NULL CHECK (length(patch_sha256) = 32),
    patch_size bigint NOT NULL,
    patch_key text NOT NULL,
    signed_manifest bytea NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT uq_delta_base UNIQUE (tenant_id, firmware_id, base_sha256)
);

CREATE TABLE campaigns (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    firmware_id uuid NOT NULL REFERENCES firmware (id),
    target jsonb NOT NULL,
    delta boolean NOT NULL,
    severity text NOT NULL CHECK (severity IN ('normal', 'security')),
    stages jsonb NOT NULL,
    current_stage integer NOT NULL,
    state text NOT NULL CHECK (state IN ('draft', 'running', 'paused', 'halted', 'completed', 'rolled_back', 'cancelled')),
    halt_reason text,
    created_by text,
    created_at timestamptz NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    parent_campaign_id uuid REFERENCES campaigns (id),
    requires_approval boolean NOT NULL,
    approved_by text,
    approved_at timestamptz,
    updated_at timestamptz NOT NULL
);
CREATE INDEX ix_campaigns_created ON campaigns (tenant_id, created_at, id);
CREATE INDEX ix_campaigns_state ON campaigns (tenant_id, state);

CREATE TABLE campaign_devices (
    tenant_id uuid NOT NULL,
    campaign_id uuid NOT NULL REFERENCES campaigns (id),
    device_id text NOT NULL CHECK (device_id ~ '^dev-[0-9a-f]{16}$'),
    stage_index integer NOT NULL,
    rank integer NOT NULL,
    state text NOT NULL,
    progress_pct integer NOT NULL CHECK (progress_pct BETWEEN 0 AND 100),
    error text,
    notified_at timestamptz,
    updated_at timestamptz NOT NULL,
    fw_hash bytea,
    from_fw_hash bytea,
    delta_from bytea,
    delta_fallback boolean NOT NULL,
    last_notified_at timestamptz,
    notify_count integer NOT NULL,
    acknowledged boolean NOT NULL,
    CONSTRAINT pk_campaign_devices PRIMARY KEY (campaign_id, device_id)
);
CREATE INDEX ix_campaign_devices_stage ON campaign_devices (campaign_id, stage_index, state);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    at timestamptz NOT NULL,
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    actor_name text,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    outcome text NOT NULL CHECK (outcome IN ('success', 'failure')),
    ip text,
    request_id text,
    details jsonb NOT NULL
);
CREATE INDEX ix_audit_target ON audit_events (tenant_id, target_type, target_id, at);

CREATE TABLE idempotency_keys (
    tenant_id uuid NOT NULL,
    actor text NOT NULL,
    key text NOT NULL,
    method text NOT NULL,
    path text NOT NULL,
    status_code integer NOT NULL,
    body jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    CONSTRAINT pk_idempotency PRIMARY KEY (tenant_id, actor, key)
);

CREATE TABLE device_seq (
    tenant_id uuid NOT NULL,
    device_id text NOT NULL,
    last_seq numeric(20, 0) NOT NULL,
    CONSTRAINT pk_device_seq PRIMARY KEY (tenant_id, device_id)
);

-- Identifier-only tables without RLS: the rollout controller's work queue and the global set of
-- signed image hashes (no tenant business data; see repository/base.py).
CREATE TABLE campaign_schedule (
    campaign_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE TABLE firmware_hash_index (
    product text NOT NULL,
    sha256_hex text NOT NULL CHECK (sha256_hex ~ '^[0-9a-f]{64}$'),
    CONSTRAINT pk_firmware_hash_index PRIMARY KEY (product, sha256_hex)
);
"""

GRANTS = """
GRANT USAGE ON SCHEMA public TO ota_app;
-- Released firmware, signed deltas and the audit trail are append-only for the service role.
GRANT SELECT, INSERT ON firmware, firmware_deltas, audit_events, firmware_hash_index TO ota_app;
GRANT SELECT, INSERT, UPDATE ON campaigns, campaign_devices, device_seq TO ota_app;
GRANT SELECT, INSERT, DELETE ON idempotency_keys, campaign_schedule TO ota_app;
"""


def _statements(script: str) -> list[str]:
    """asyncpg runs one statement per call: drop comment lines and split on ``;``."""
    lines = [line for line in script.splitlines() if not line.lstrip().startswith("--")]
    body = "\n".join(lines)
    return [stmt.strip() for stmt in body.split(";") if stmt.strip()]


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ota_app') THEN
                CREATE ROLE ota_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
            END IF;
        END
        $$;
        """
    )
    for statement in _statements(DDL):
        op.execute(statement)
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING ({TENANT_PREDICATE}) WITH CHECK ({TENANT_PREDICATE})"
        )
    for statement in _statements(GRANTS):
        op.execute(statement)


def downgrade() -> None:
    for table in (
        "firmware_hash_index",
        "campaign_schedule",
        "device_seq",
        "idempotency_keys",
        "audit_events",
        "campaign_devices",
        "campaigns",
        "firmware_deltas",
        "firmware",
    ):
        op.execute(f"DROP TABLE IF EXISTS {table}")
