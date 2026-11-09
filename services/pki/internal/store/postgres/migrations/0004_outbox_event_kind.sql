-- IronMesh PKI: event kinds in the revocation outbox.
--
-- The outbox now carries two kinds of Policy events, delivered with the same
-- signed push, retries and DNS fan-out:
--   revocation      a certificate revocation (every row written before this
--                   migration; the column default keeps them that kind)
--   device_release  POST /v1/devices/{id}/release from the registry: the
--                   Policy service lifts the device-level deny that a
--                   quarantine (revoke-all, device_deny) installed
--
-- Same isolation model as 0003: the tenant_isolation policy stays, row-level
-- security is (re-)forced for every role and pki_app keeps SELECT, INSERT,
-- UPDATE (no DELETE/TRUNCATE).

ALTER TABLE revocation_outbox
    ADD COLUMN IF NOT EXISTS event_kind TEXT NOT NULL DEFAULT 'revocation';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                 WHERE conname = 'revocation_outbox_event_kind_check'
                   AND conrelid = 'revocation_outbox'::regclass) THEN
    ALTER TABLE revocation_outbox
      ADD CONSTRAINT revocation_outbox_event_kind_check
      CHECK (event_kind IN ('revocation', 'device_release'));
  END IF;
END
$$;

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
