"""Initial registry schema: tables, indexes, row-level security, roles, grants, functions.

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-09

Runs as the schema owner (``REGISTRY_MIGRATION_DATABASE_URL``). The application connects as the
non-owner role ``registry_app`` (NOBYPASSRLS), which is created here without a password; operators
set one with ``ALTER ROLE registry_app PASSWORD ...`` (or use IAM / cert auth).

Tenancy (design contract section 8): every tenant table has ``tenant_id uuid NOT NULL``, RLS is
ENABLEd and FORCEd, and the ``tenant_isolation`` policy for ``registry_app`` is exactly
``tenant_id = current_setting('ironmesh.tenant_id')::uuid``. An unset or empty setting makes every
query fail (fail closed) instead of returning rows. A second policy grants the schema owner (and
therefore the SECURITY DEFINER functions below) unrestricted access for maintenance.
"""

from __future__ import annotations

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

TENANT_TABLES = (
    "tenants",
    "tenant_keys",
    "devices",
    "certificates",
    "groups",
    "group_members",
    "twins",
    "commands",
    "device_configs",
    "timeline_events",
    "telemetry_samples",
    "device_replay",
    "alerts",
    "audit_events",
    "audit_heads",
    "users",
    "api_keys",
    "pending_actions",
    "ingest_stats",
)

TABLES = r"""
CREATE TABLE tenants (
    tenant_id   uuid PRIMARY KEY,
    name        text NOT NULL,
    settings    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tenant_keys (
    tenant_id         uuid PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    kek_id            text NOT NULL,
    wrapped_data_key  bytea NOT NULL,
    wrapped_cmd_key   bytea NOT NULL,
    cmd_public_key    bytea NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id                     text PRIMARY KEY CHECK (id ~ '^dev-[0-9a-f]{16}$'),
    tenant_id              uuid NOT NULL REFERENCES tenants(tenant_id),
    product                text NOT NULL,
    hw_revision            text NOT NULL,
    state                  text NOT NULL CHECK (state IN ('manufactured','provisioned','active','quarantined','decommissioned')),
    se_type                text CHECK (se_type IN ('atecc608','tpm2','optee','software')),
    assurance_level        text CHECK (assurance_level IN ('hardware','software')),
    bootstrap_serial_hex   text,
    tags                   jsonb NOT NULL DEFAULT '{}'::jsonb,
    connected              boolean NOT NULL DEFAULT false,
    last_seen_at           timestamptz,
    fw_version             text,
    fw_hash_hex            text,
    cert_serial_hex        text,
    cert_not_after         timestamptz,
    cert_revoked           boolean NOT NULL DEFAULT false,
    lat                    double precision,
    lon                    double precision,
    created_at             timestamptz NOT NULL DEFAULT now(),
    provisioned_at         timestamptz,
    activated_at           timestamptz,
    quarantined_at         timestamptz,
    quarantine_reason      text,
    decommissioned_at      timestamptz,
    downlink_seq           bigint NOT NULL DEFAULT 0,
    provisioning_status    text NOT NULL DEFAULT 'pending' CHECK (provisioning_status IN ('pending','failed','done')),
    provisioning_attempts  integer NOT NULL DEFAULT 0,
    last_attempt_at        timestamptz,
    last_error             text,
    last_telemetry         jsonb
);
CREATE INDEX devices_tenant_id_idx ON devices (tenant_id, id);
CREATE INDEX devices_tenant_state_idx ON devices (tenant_id, state);
CREATE INDEX devices_tags_idx ON devices USING gin (tags);

CREATE TABLE certificates (
    serial_hex         text PRIMARY KEY,
    tenant_id          uuid NOT NULL REFERENCES tenants(tenant_id),
    device_id          text NOT NULL REFERENCES devices(id),
    kind               text NOT NULL DEFAULT 'operational',
    issuer             text NOT NULL,
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    assurance_level    text,
    revoked_at         timestamptz,
    revocation_reason  text,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX certificates_device_idx ON certificates (tenant_id, device_id);

CREATE TABLE groups (
    tenant_id      uuid NOT NULL REFERENCES tenants(tenant_id),
    slug           text NOT NULL CHECK (slug ~ '^[a-z0-9-]{1,48}$'),
    name           text NOT NULL,
    description    text,
    hardware_only  boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, slug)
);

CREATE TABLE group_members (
    tenant_id  uuid NOT NULL,
    slug       text NOT NULL,
    device_id  text NOT NULL REFERENCES devices(id),
    PRIMARY KEY (tenant_id, slug, device_id),
    FOREIGN KEY (tenant_id, slug) REFERENCES groups(tenant_id, slug) ON DELETE CASCADE
);
CREATE INDEX group_members_device_idx ON group_members (tenant_id, device_id);

CREATE TABLE twins (
    device_id            text PRIMARY KEY REFERENCES devices(id),
    tenant_id            uuid NOT NULL REFERENCES tenants(tenant_id),
    version              bigint NOT NULL DEFAULT 0,
    desired              jsonb NOT NULL DEFAULT '{}'::jsonb,
    reported             jsonb NOT NULL DEFAULT '{}'::jsonb,
    reported_version     bigint NOT NULL DEFAULT 0,
    desired_updated_at   timestamptz,
    reported_updated_at  timestamptz
);

CREATE TABLE commands (
    cmd_id            uuid PRIMARY KEY,
    tenant_id         uuid NOT NULL REFERENCES tenants(tenant_id),
    device_id         text NOT NULL REFERENCES devices(id),
    name              text NOT NULL,
    args              jsonb NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key   text NOT NULL,
    request_hash      text NOT NULL,
    status            text NOT NULL CHECK (status IN ('pending','sent','acked','failed','rejected','expired')),
    created_by        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    sent_at           timestamptz,
    acked_at          timestamptz,
    expires_at        timestamptz NOT NULL,
    result            jsonb,
    error             text,
    nonce             bytea NOT NULL,
    batch_id          uuid,
    publish_attempts  integer NOT NULL DEFAULT 0,
    CONSTRAINT commands_idempotency_uq UNIQUE (tenant_id, device_id, idempotency_key)
);
CREATE INDEX commands_device_idx ON commands (tenant_id, device_id, created_at DESC, cmd_id DESC);
CREATE INDEX commands_open_idx ON commands (tenant_id, expires_at) WHERE status IN ('pending','sent');

CREATE TABLE device_configs (
    device_id     text PRIMARY KEY REFERENCES devices(id),
    tenant_id     uuid NOT NULL REFERENCES tenants(tenant_id),
    version       bigint NOT NULL,
    ciphertext    bytea NOT NULL,
    iv            bytea NOT NULL,
    updated_at    timestamptz NOT NULL,
    updated_by    text,
    published_at  timestamptz,
    delivered_at  timestamptz,
    acked_at      timestamptz
);

CREATE TABLE timeline_events (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(tenant_id),
    device_id  text NOT NULL,
    at         timestamptz NOT NULL,
    kind       text NOT NULL,
    summary    text NOT NULL,
    data       jsonb
);
CREATE INDEX timeline_device_idx ON timeline_events (tenant_id, device_id, at DESC, id DESC);

CREATE TABLE telemetry_samples (
    tenant_id     uuid NOT NULL,
    device_id     text NOT NULL,
    at            timestamptz NOT NULL,
    cpu_pct       double precision,
    mem_pct       double precision,
    temp_c        double precision,
    net_rx_bytes  double precision,
    net_tx_bytes  double precision,
    rssi          double precision,
    free_heap     double precision,
    extra         jsonb NOT NULL DEFAULT '{}'::jsonb
) PARTITION BY RANGE (at);
CREATE INDEX telemetry_device_at_idx ON telemetry_samples (tenant_id, device_id, at);
CREATE TABLE telemetry_samples_default PARTITION OF telemetry_samples DEFAULT;

CREATE TABLE device_replay (
    device_id  text NOT NULL,
    direction  text NOT NULL CHECK (direction IN ('uplink','downlink')),
    tenant_id  uuid NOT NULL,
    last_seq   numeric(20,0) NOT NULL,
    PRIMARY KEY (device_id, direction)
);

CREATE TABLE alerts (
    id          text PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    device_id   text NOT NULL,
    rule        text NOT NULL,
    severity    text NOT NULL,
    state       text NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL
);
CREATE INDEX alerts_open_idx ON alerts (tenant_id, device_id) WHERE state = 'open';

CREATE TABLE audit_events (
    tenant_id    uuid NOT NULL,
    seq          bigint NOT NULL,
    id           uuid NOT NULL UNIQUE,
    at           timestamptz NOT NULL,
    actor_type   text NOT NULL,
    actor_id     text NOT NULL,
    actor_name   text,
    action       text NOT NULL,
    target_type  text NOT NULL,
    target_id    text NOT NULL,
    outcome      text NOT NULL CHECK (outcome IN ('success','failure')),
    ip           text,
    request_id   text,
    body         text NOT NULL,
    prev_hash    bytea NOT NULL,
    hash         bytea NOT NULL,
    PRIMARY KEY (tenant_id, seq)
);
CREATE INDEX audit_target_idx ON audit_events (tenant_id, target_type, target_id, seq DESC);
CREATE INDEX audit_at_idx ON audit_events (tenant_id, at);

CREATE TABLE audit_heads (
    tenant_id  uuid PRIMARY KEY,
    last_seq   bigint NOT NULL,
    last_hash  bytea NOT NULL
);

CREATE TABLE users (
    tenant_id      uuid NOT NULL REFERENCES tenants(tenant_id),
    id             text NOT NULL,
    email          text NOT NULL,
    name           text,
    role           text NOT NULL CHECK (role IN ('owner','admin','operator','viewer','factory')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE api_keys (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(tenant_id),
    name          text NOT NULL,
    prefix        text NOT NULL,
    key_hash      bytea NOT NULL UNIQUE,
    role          text NOT NULL CHECK (role IN ('owner','admin','operator','viewer','factory')),
    scopes        jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    text,
    last_used_at  timestamptz,
    expires_at    timestamptz,
    revoked_at    timestamptz
);

CREATE TABLE pending_actions (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL,
    kind             text NOT NULL,
    device_id        text NOT NULL,
    payload          jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz NOT NULL,
    next_attempt_at  timestamptz NOT NULL,
    attempts         integer NOT NULL DEFAULT 0,
    status           text NOT NULL DEFAULT 'pending',
    last_error       text
);
CREATE INDEX pending_actions_due_idx ON pending_actions (tenant_id, next_attempt_at) WHERE status = 'pending';

CREATE TABLE ingest_stats (
    tenant_id        uuid NOT NULL,
    minute           timestamptz NOT NULL,
    messages         bigint NOT NULL DEFAULT 0,
    rejected         bigint NOT NULL DEFAULT 0,
    replay_rejected  bigint NOT NULL DEFAULT 0,
    auth_failures    bigint NOT NULL DEFAULT 0,
    connects         bigint NOT NULL DEFAULT 0,
    p99_ms           double precision NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, minute)
);

-- Audit rows are append-only, even for the owner (the trigger must be dropped explicitly).
CREATE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();
"""

FUNCTIONS = r"""
CREATE FUNCTION registry_device_tenant(p_device_id text) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT tenant_id FROM public.devices WHERE id = p_device_id
$$;

CREATE FUNCTION registry_api_key_lookup(p_hash bytea) RETURNS SETOF public.api_keys
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT * FROM public.api_keys WHERE key_hash = p_hash
$$;

CREATE FUNCTION registry_tenant_ids() RETURNS SETOF uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT tenant_id FROM public.tenants ORDER BY tenant_id
$$;

CREATE FUNCTION registry_ensure_telemetry_partitions(p_days_ahead integer) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    d date;
    created integer := 0;
    part text;
BEGIN
    FOR d IN SELECT generate_series(current_date - 1, current_date + GREATEST(p_days_ahead, 0), interval '1 day')::date LOOP
        part := 'telemetry_samples_' || to_char(d, 'YYYYMMDD');
        IF to_regclass('public.' || part) IS NULL THEN
            BEGIN
                EXECUTE format(
                    'CREATE TABLE public.%I PARTITION OF public.telemetry_samples FOR VALUES FROM (%L) TO (%L)',
                    part, d::timestamptz, (d + 1)::timestamptz);
                EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', part);
                EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', part);
                created := created + 1;
            EXCEPTION WHEN check_violation THEN
                RAISE NOTICE 'partition % overlaps rows in the default partition; skipped', part;
            END;
        END IF;
    END LOOP;
    RETURN created;
END $$;

CREATE FUNCTION registry_drop_telemetry_partitions(p_retain_days integer) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    r record;
    dropped integer := 0;
    cutoff date := current_date - GREATEST(p_retain_days, 1);
BEGIN
    FOR r IN
        SELECT c.relname FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'telemetry_samples' AND c.relname ~ '^telemetry_samples_[0-9]{8}$'
    LOOP
        IF to_date(substr(r.relname, 19), 'YYYYMMDD') < cutoff THEN
            EXECUTE format('DROP TABLE public.%I', r.relname);
            dropped := dropped + 1;
        END IF;
    END LOOP;
    DELETE FROM public.telemetry_samples_default WHERE at < cutoff::timestamptz;
    RETURN dropped;
END $$;
"""


def statements(sql: str) -> list[str]:
    """Split a script on top-level ``;`` (respecting quotes and ``$$`` bodies)."""
    out: list[str] = []
    buf: list[str] = []
    in_dollar = in_quote = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if not in_quote and sql.startswith("$$", i):
            in_dollar = not in_dollar
            buf.append("$$")
            i += 2
            continue
        if not in_dollar and ch == "'":
            in_quote = not in_quote
        if ch == ";" and not in_dollar and not in_quote:
            stmt = "".join(buf).strip()
            if stmt and not all(line.strip().startswith("--") for line in stmt.splitlines()):
                out.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def upgrade() -> None:
    op.execute(
        """
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'registry_app') THEN
                CREATE ROLE registry_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
            END IF;
        END $$;
        """
    )
    for stmt in statements(TABLES) + statements(FUNCTIONS):
        op.execute(stmt)
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} TO registry_app "
            "USING (tenant_id = current_setting('ironmesh.tenant_id')::uuid) "
            "WITH CHECK (tenant_id = current_setting('ironmesh.tenant_id')::uuid)"
        )
        op.execute(
            "DO $$ BEGIN EXECUTE format("
            f"'CREATE POLICY owner_maintenance ON {table} TO %I USING (true) WITH CHECK (true)', "
            "current_user); END $$;"
        )
    op.execute("ALTER TABLE telemetry_samples_default ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE telemetry_samples_default FORCE ROW LEVEL SECURITY")
    op.execute("GRANT USAGE ON SCHEMA public TO registry_app")
    writable = [t for t in TENANT_TABLES if t != "audit_events"]
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {', '.join(writable)} TO registry_app")
    op.execute("GRANT SELECT, INSERT ON audit_events TO registry_app")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM registry_app")
    for fn in (
        "registry_device_tenant(text)",
        "registry_api_key_lookup(bytea)",
        "registry_tenant_ids()",
        "registry_ensure_telemetry_partitions(integer)",
        "registry_drop_telemetry_partitions(integer)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {fn} TO registry_app")
    op.execute("SELECT registry_ensure_telemetry_partitions(3)")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events")
    for fn in (
        "registry_device_tenant(text)",
        "registry_api_key_lookup(bytea)",
        "registry_tenant_ids()",
        "registry_ensure_telemetry_partitions(integer)",
        "registry_drop_telemetry_partitions(integer)",
        "audit_events_immutable()",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {fn} CASCADE")
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
