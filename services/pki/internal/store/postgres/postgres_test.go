package postgres

import (
	"context"
	"os"
	"testing"
	"testing/fstest"
	"time"

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
