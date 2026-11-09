-- IronMesh PKI: enforce row-level security for every role and grant the
-- non-owner runtime role pki_app (DESIGN_CONTRACT §8, same pattern as
-- registry_app / ota_app / anomaly_app).
--
-- Run as the schema owner (PKI_MIGRATION_DATABASE_URL). The service then
-- connects with PKI_DATABASE_URL as pki_app, which owns nothing and has
-- NOBYPASSRLS, so the tenant_isolation policies always apply to it. The
-- policies keep their 0001 semantics: an unset ironmesh.tenant_id means a
-- service-wide operation (CRL, OCSP, stats) and sees every row.
--
-- pki_app is created here when the migrating role may create roles;
-- otherwise it must exist already (deploy/docker/postgres/10-ironmesh.sh
-- creates pki_owner and pki_app). It is created without a password: set one
-- with ALTER ROLE pki_app PASSWORD ... or use RDS IAM authentication
-- (GRANT rds_iam TO pki_app, done below when the rds_iam role exists).

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pki_app') THEN
    BEGIN
      CREATE ROLE pki_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    EXCEPTION WHEN insufficient_privilege THEN
      RAISE NOTICE 'role pki_app does not exist and % may not create roles; create it out of band and re-run the grants', current_user;
    END;
  END IF;
END
$$;

DO $$
DECLARE t text;
BEGIN
  -- Every table that carries tenant data and a tenant_isolation policy.
  FOREACH t IN ARRAY ARRAY['certificates', 'revocations', 'nonces', 'tenant_policies']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
  END LOOP;

  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pki_app') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA public TO pki_app';
    -- Least privilege per table, matching internal/store/postgres/postgres.go:
    -- certificates and revocations are append-only; nonces are consumed with
    -- DELETE ... RETURNING; tenant policies are upserted.
    EXECUTE 'GRANT SELECT, INSERT ON certificates TO pki_app';
    EXECUTE 'GRANT SELECT, INSERT ON revocations TO pki_app';
    EXECUTE 'GRANT SELECT, INSERT, DELETE ON nonces TO pki_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON tenant_policies TO pki_app';
    EXECUTE 'GRANT SELECT, UPDATE ON crl_counter TO pki_app';
    EXECUTE 'GRANT SELECT ON schema_migrations TO pki_app';
    EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON certificates, revocations FROM pki_app';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rds_iam') THEN
      BEGIN
        EXECUTE 'GRANT rds_iam TO pki_app';
      EXCEPTION WHEN insufficient_privilege THEN
        RAISE NOTICE 'cannot grant rds_iam to pki_app as %; grant it out of band for PKI_DB_IAM_AUTH', current_user;
      END;
    END IF;
  END IF;
END
$$;
