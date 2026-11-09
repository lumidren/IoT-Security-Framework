-- IronMesh PKI: durable revocation outbox (THREAT_MODEL T-26, T-70).
--
-- Every revocation that must reach the Policy service is written here in the
-- same transaction as the revocations row. A background dispatcher delivers
-- pending rows (to every Policy replica with PKI_POLICY_FANOUT=dns) with
-- exponential backoff and marks them delivered only once every endpoint
-- acknowledged, so a Policy outage or a PKI restart no longer loses the push.
--
-- Same isolation model as 0001/0002: tenant_isolation policy, row-level
-- security forced for every role, least-privilege grants to pki_app (rows
-- are claimed and acknowledged with UPDATE, never deleted by the service).

CREATE TABLE IF NOT EXISTS revocation_outbox (
    event_id         TEXT PRIMARY KEY,
    tenant_id        UUID NOT NULL,
    payload          BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NOT NULL,
    last_error       TEXT NOT NULL DEFAULT '',
    delivered_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS revocation_outbox_pending_idx
    ON revocation_outbox (next_attempt_at, created_at) WHERE delivered_at IS NULL;

ALTER TABLE revocation_outbox ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON revocation_outbox;
CREATE POLICY tenant_isolation ON revocation_outbox USING (
    COALESCE(current_setting('ironmesh.tenant_id', true), '') = ''
    OR tenant_id = current_setting('ironmesh.tenant_id', true)::uuid);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['revocation_outbox']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
  END LOOP;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pki_app') THEN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON revocation_outbox TO pki_app';
    EXECUTE 'REVOKE DELETE, TRUNCATE ON revocation_outbox FROM pki_app';
  END IF;
END
$$;
