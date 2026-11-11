#!/usr/bin/env bash
# Runs once on an empty data directory (/docker-entrypoint-initdb.d). Creates the four IronMesh
# databases and, per database, the roles the services and their migrations expect:
#
#   <db>_owner  LOGIN, owns the database and the public schema; runs the migrations
#               (REGISTRY_MIGRATION_DATABASE_URL, OTA_MIGRATION_DATABASE_URL,
#               ANOMALY_DATABASE_MIGRATE_URL, PKI_MIGRATION_DATABASE_URL: the pki service applies
#               its embedded migrations at start with that owner DSN, then runs as pki_app)
#   <db>_app    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS, runtime role
#               (REGISTRY_DB_USER, OTA_DB_USER, ANOMALY_DB_USER, the PKI_DATABASE_URL user); owns
#               nothing so row-level security applies. Table grants come from each service's
#               migration (registry 0001/0002, ota 0001/0002, anomaly 001_init.sql, pki
#               0002_force_rls_app_role.sql), so append-only tables stay append-only.
#   ironmesh_backup  LOGIN, BYPASSRLS, pg_read_all_data (scripts/backup/pg_backup.sh)
#
# Passwords are read from compose secrets (/run/secrets/<db>_db_owner_password,
# /run/secrets/<db>_db_password, /run/secrets/backup_db_password); nothing is passed on argv.
#
# The docker-entrypoint sources *.sh files that are not executable, so the body runs in a
# subshell: strict mode and exit codes never leak into the entrypoint itself.
(
set -euo pipefail

secret() {
  local file="/run/secrets/$1"
  if [[ ! -s "${file}" ]]; then
    echo "10-ironmesh.sh: missing secret ${file}" >&2
    exit 1
  fi
  tr -d '\r\n' < "${file}"
}

psql_admin() {
  psql -v ON_ERROR_STOP=1 -X -q --username "${POSTGRES_USER}" "$@"
}

for db in pki registry ota anomaly; do
  owner="${db}_owner"
  app="${db}_app"
  owner_pw="$(secret "${db}_db_owner_password")"
  app_pw="$(secret "${db}_db_password")"

  psql_admin -d postgres -v owner="${owner}" -v app="${app}" -v owner_pw="${owner_pw}" \
    -v app_pw="${app_pw}" -v db="${db}" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', :'owner', :'owner_pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'owner') \gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L', :'app', :'app_pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app') \gexec
-- A pre-existing runtime role (e.g. created by a migration) must still never bypass RLS.
SELECT format('ALTER ROLE %I NOBYPASSRLS', :'app') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'db', :'owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') \gexec
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \gexec
SELECT format('GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I', :'db', :'app') \gexec
SQL

  psql_admin -d "${db}" -v owner="${owner}" -v app="${app}" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('ALTER SCHEMA public OWNER TO %I', :'owner') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'app') \gexec
SQL
  echo "10-ironmesh.sh: database ${db} ready (${owner}, ${app})"
done

backup_pw="$(secret backup_db_password)"
psql_admin -d postgres -v pw="${backup_pw}" <<'SQL'
SELECT format('CREATE ROLE ironmesh_backup LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', :'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ironmesh_backup') \gexec
-- pg_dump refuses tables with (forced) row-level security unless the role bypasses RLS, and the
-- registry policies error when no tenant is set, so the read-only backup role needs BYPASSRLS.
ALTER ROLE ironmesh_backup BYPASSRLS;
GRANT pg_read_all_data TO ironmesh_backup;
SQL
for db in pki registry ota anomaly; do
  psql_admin -d postgres -v db="${db}" <<'SQL'
SELECT format('GRANT CONNECT ON DATABASE %I TO ironmesh_backup', :'db') \gexec
SQL
done
echo "10-ironmesh.sh: done"
)
