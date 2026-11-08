-- IronMesh anomaly service schema. Every tenant table has tenant_id uuid NOT NULL and a forced
-- row-level-security policy bound to the per-transaction setting ironmesh.tenant_id
-- (DESIGN_CONTRACT section 8). The service connects as the non-owner role anomaly_app.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anomaly_app') THEN
    CREATE ROLE anomaly_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS anomaly_tenants (
  tenant_id  uuid PRIMARY KEY,
  first_seen timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS alerts (
  tenant_id    uuid        NOT NULL,
  id           uuid        NOT NULL,
  device_id    text        NOT NULL,
  rule         text        NOT NULL,
  severity     text        NOT NULL,
  state        text        NOT NULL,
  created_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  record       jsonb       NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS alerts_list_idx ON alerts (tenant_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS alerts_active_idx ON alerts (tenant_id, device_id, rule, last_seen_at)
  WHERE state <> 'resolved';

CREATE TABLE IF NOT EXISTS rule_overrides (
  tenant_id  uuid        NOT NULL,
  name       text        NOT NULL,
  override   jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS tenant_settings (
  tenant_id  uuid PRIMARY KEY,
  settings   jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS quarantine_records (
  tenant_id      uuid        NOT NULL,
  device_id      text        NOT NULL,
  quarantined_at timestamptz NOT NULL,
  reason         text        NOT NULL,
  alert_id       uuid,
  by_actor       text        NOT NULL,
  PRIMARY KEY (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS suppressions (
  tenant_id  uuid        NOT NULL,
  device_id  text        NOT NULL,
  rule       text        NOT NULL,
  until      timestamptz NOT NULL,
  count      integer     NOT NULL,
  created_by text        NOT NULL,
  PRIMARY KEY (tenant_id, device_id, rule)
);

CREATE TABLE IF NOT EXISTS device_events (
  tenant_id uuid        NOT NULL,
  ts        timestamptz NOT NULL,
  device_id text        NOT NULL,
  kind      text        NOT NULL,
  data      jsonb       NOT NULL
);
CREATE INDEX IF NOT EXISTS device_events_ts_idx ON device_events (tenant_id, ts);

CREATE TABLE IF NOT EXISTS device_states (
  tenant_id  uuid        NOT NULL,
  device_id  text        NOT NULL,
  state      jsonb       NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS models (
  tenant_id    uuid        NOT NULL,
  device_class text        NOT NULL,
  version      text        NOT NULL,
  sha256_hex   text        NOT NULL CHECK (sha256_hex ~ '^[0-9a-f]{64}$'),
  trained_at   timestamptz NOT NULL,
  samples      integer     NOT NULL,
  metadata     jsonb       NOT NULL,
  PRIMARY KEY (tenant_id, device_class, version)
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['alerts', 'rule_overrides', 'tenant_settings', 'quarantine_records',
                           'suppressions', 'device_events', 'device_states', 'models']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING '
      '(tenant_id = NULLIF(current_setting(''ironmesh.tenant_id'', true), '''')::uuid) '
      'WITH CHECK (tenant_id = NULLIF(current_setting(''ironmesh.tenant_id'', true), '''')::uuid)',
      t);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO anomaly_app', t);
  END LOOP;
END
$$;

-- anomaly_tenants holds only tenant ids (no tenant data) so start-up can enumerate tenants.
GRANT SELECT, INSERT ON anomaly_tenants TO anomaly_app;
