-- IronMesh PKI schema. Applied by the built-in migration runner (migrate.go).

CREATE TABLE IF NOT EXISTS certificates (
    serial       TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL,
    tenant_id    UUID NOT NULL,
    kind         TEXT NOT NULL,
    issuer_cn    TEXT NOT NULL,
    not_before   TIMESTAMPTZ NOT NULL,
    not_after    TIMESTAMPTZ NOT NULL,
    spki_sha256  TEXT NOT NULL,
    assurance    TEXT NOT NULL DEFAULT '',
    der          BYTEA NOT NULL,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS certificates_device_idx ON certificates (device_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS certificates_not_after_idx ON certificates (not_after);
CREATE INDEX IF NOT EXISTS certificates_tenant_idx ON certificates (tenant_id);

CREATE TABLE IF NOT EXISTS revocations (
    serial      TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    tenant_id   UUID NOT NULL,
    issuer_cn   TEXT NOT NULL,
    not_after   TIMESTAMPTZ NOT NULL,
    reason      SMALLINT NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS revocations_issuer_idx ON revocations (issuer_cn, not_after);

CREATE TABLE IF NOT EXISTS nonces (
    value       TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    tenant_id   UUID NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS nonces_expires_idx ON nonces (expires_at);

CREATE TABLE IF NOT EXISTS crl_counter (
    id      SMALLINT PRIMARY KEY CHECK (id = 1),
    number  BIGINT NOT NULL
);
INSERT INTO crl_counter (id, number) VALUES (1, 0) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id            UUID PRIMARY KEY,
    allow_software_keys  BOOLEAN NOT NULL DEFAULT false,
    allowed_pcr_digests  TEXT[] NOT NULL DEFAULT '{}',
    ak_ca_pem            TEXT NOT NULL DEFAULT '',
    tenant_cmd_pubkey    BYTEA,
    fw_signing_pubkeys   BYTEA[] NOT NULL DEFAULT '{}',
    broker_host          TEXT NOT NULL DEFAULT '',
    broker_port          INTEGER NOT NULL DEFAULT 0,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Row-level security (DESIGN_CONTRACT §8). Tenant-scoped sessions set
-- ironmesh.tenant_id; service-wide operations (CRL generation, OCSP) run
-- without the setting and see every row. The application role must not own
-- the tables so that RLS applies to it.
ALTER TABLE certificates    ENABLE ROW LEVEL SECURITY;
ALTER TABLE revocations     ENABLE ROW LEVEL SECURITY;
ALTER TABLE nonces          ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_policies ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON certificates;
CREATE POLICY tenant_isolation ON certificates USING (
    COALESCE(current_setting('ironmesh.tenant_id', true), '') = ''
    OR tenant_id = current_setting('ironmesh.tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON revocations;
CREATE POLICY tenant_isolation ON revocations USING (
    COALESCE(current_setting('ironmesh.tenant_id', true), '') = ''
    OR tenant_id = current_setting('ironmesh.tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON nonces;
CREATE POLICY tenant_isolation ON nonces USING (
    COALESCE(current_setting('ironmesh.tenant_id', true), '') = ''
    OR tenant_id = current_setting('ironmesh.tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_isolation ON tenant_policies;
CREATE POLICY tenant_isolation ON tenant_policies USING (
    COALESCE(current_setting('ironmesh.tenant_id', true), '') = ''
    OR tenant_id = current_setting('ironmesh.tenant_id', true)::uuid);
