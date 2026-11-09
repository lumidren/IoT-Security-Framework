package postgres

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store/storetest"
)

func TestLoadMigrations(t *testing.T) {
	t.Parallel()
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatalf("LoadMigrations: %v", err)
	}
	if len(ms) == 0 || ms[0].Version != 1 || ms[0].Name != "0001_init.sql" || ms[0].SQL == "" {
		t.Fatalf("unexpected migrations: %+v", ms)
	}
	for i := 1; i < len(ms); i++ {
		if ms[i].Version <= ms[i-1].Version {
			t.Fatalf("migrations not sorted: %v", ms)
		}
	}
}

func TestLoadMigrationsValidation(t *testing.T) {
	t.Parallel()
	cases := map[string]fstest.MapFS{
		"no underscore": {"migrations/0001.sql": {Data: []byte("select 1")}},
		"bad version":   {"migrations/abcd_x.sql": {Data: []byte("select 1")}},
		"zero version":  {"migrations/0000_x.sql": {Data: []byte("select 1")}},
		"duplicate":     {"migrations/0001_a.sql": {Data: []byte("a")}, "migrations/1_b.sql": {Data: []byte("b")}},
		"missing dir":   {"other/0001_a.sql": {Data: []byte("a")}},
	}
	for name, fsys := range cases {
		if _, err := loadMigrations(fsys); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	ok := fstest.MapFS{
		"migrations/0002_b.sql": {Data: []byte("b")},
		"migrations/0001_a.sql": {Data: []byte("a")},
		"migrations/README.md":  {Data: []byte("ignored")},
	}
	ms, err := loadMigrations(ok)
	if err != nil || len(ms) != 2 || ms[0].Name != "0001_a.sql" || ms[1].Name != "0002_b.sql" {
		t.Fatalf("unexpected result: %+v, %v", ms, err)
	}
}

func TestOpenInvalidURL(t *testing.T) {
	t.Parallel()
	if _, err := Open(context.Background(), "::not-a-url"); err == nil {
		t.Fatal("expected parse error")
	}
}

// TestPostgresConformance runs the shared store suite against a live database.
func TestPostgresConformance(t *testing.T) {
	url := os.Getenv("PKI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PKI_TEST_DATABASE_URL not set; skipping Postgres integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	storetest.Run(t, func(t *testing.T) store.Store {
		if err := s.Truncate(context.Background()); err != nil {
			t.Fatalf("Truncate: %v", err)
		}
		return s
	})
}

func TestPoolConfig(t *testing.T) {
	t.Parallel()
	called := false
	cfg, err := PoolConfig("postgres://pki_app@db:5432/pki?sslmode=require", Options{
		MaxConns:      4,
		BeforeConnect: func(context.Context, *pgx.ConnConfig) error { called = true; return nil },
	})
	if err != nil || cfg.MaxConns != 4 || cfg.MinConns != 1 || cfg.BeforeConnect == nil {
		t.Fatalf("pool config %+v %v", cfg, err)
	}
	_ = cfg.BeforeConnect(context.Background(), cfg.ConnConfig)
	if !called {
		t.Fatal("hook not installed")
	}
	if cfg, err := PoolConfig("postgres://db/pki", Options{}); err != nil || cfg.MaxConns != 16 || cfg.BeforeConnect != nil {
		t.Fatalf("defaults %+v %v", cfg, err)
	}
	if _, err := OpenWithOptions(context.Background(), "::bad", Options{}); err == nil {
		t.Fatal("bad DSN accepted")
	}
	if err := MigrateURL(context.Background(), "::bad", Options{}); err == nil {
		t.Fatal("bad migration DSN accepted")
	}
}

// TestForceRLSCoversEveryPolicyTable checks that the RLS migration forces row-level security on
// every table that has a tenant_isolation policy and grants the runtime role only what the store
// needs.
func TestForceRLSCoversEveryPolicyTable(t *testing.T) {
	t.Parallel()
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	var force string
	for _, m := range ms {
		all.WriteString(m.SQL)
		if strings.Contains(m.SQL, "FORCE ROW LEVEL SECURITY") {
			force = m.SQL
		}
	}
	if force == "" {
		t.Fatal("no migration forces row-level security")
	}
	policyTables := regexp.MustCompile(`CREATE POLICY \w+ ON (\w+)`).FindAllStringSubmatch(all.String(), -1)
	if len(policyTables) == 0 {
		t.Fatal("no policies found")
	}
	list := regexp.MustCompile(`FOREACH t IN ARRAY ARRAY\[([^\]]+)\]`).FindStringSubmatch(force)
	if list == nil {
		t.Fatal("FORCE table list not found")
	}
	for _, m := range policyTables {
		if !strings.Contains(list[1], "'"+m[1]+"'") {
			t.Errorf("table %s has a policy but RLS is not forced", m[1])
		}
	}
	for _, want := range []string{
		"CREATE ROLE pki_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS",
		"GRANT SELECT, INSERT ON certificates TO pki_app",
		"GRANT SELECT, INSERT ON revocations TO pki_app",
		"GRANT SELECT, INSERT, DELETE ON nonces TO pki_app",
		"GRANT SELECT, INSERT, UPDATE ON tenant_policies TO pki_app",
		"GRANT SELECT, UPDATE ON crl_counter TO pki_app",
	} {
		if !strings.Contains(force, want) {
			t.Errorf("migration lacks %q", want)
		}
	}
}
