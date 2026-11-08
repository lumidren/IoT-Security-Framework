package revocation

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	devA   = "dev-8f3a1c2b9d4e5f60"
	devB   = "dev-0123456789abcdef"
	tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
)

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

func fixedNow() time.Time { return t0.Add(time.Minute) }

func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{
		"0A:BC": "abc", "0x00abc": "abc", "ABC": "abc", "": "", "0": "0", "000": "0", "zz": "",
		"ab cd": "abcd", "ab-cd": "abcd", " 1f ": "1f", "0X1F": "1f", "g1": "",
	}
	for in, want := range cases {
		if got := NormalizeSerial(in); got != want {
			t.Errorf("NormalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
	if got := SerialFromBigInt(big.NewInt(0xabc)); got != "abc" {
		t.Errorf("SerialFromBigInt = %q", got)
	}
	if got := SerialFromBigInt(nil); got != "" {
		t.Errorf("SerialFromBigInt(nil) = %q", got)
	}
}

func TestUpsertAndLookups(t *testing.T) {
	c := NewCache("", nil)
	c.now = fixedNow
	added, err := c.Upsert(Entry{EventID: "e1", Serial: "0ABC", DeviceID: devA, TenantID: tenant, RevokedAt: t0})
	if err != nil || !added {
		t.Fatalf("Upsert = %v, %v", added, err)
	}
	if !c.IsRevokedDevice(devA) || c.IsRevokedDevice(devB) || c.IsRevokedDevice("") {
		t.Error("IsRevokedDevice mismatch")
	}
	for in, want := range map[string]bool{"0x0abc": true, "abc": true, "0A:BC": true, "def": false, "": false, "zz": false} {
		if got := c.IsRevokedSerial(in); got != want {
			t.Errorf("IsRevokedSerial(%q) = %v, want %v", in, got, want)
		}
	}
	if added, _ := c.Upsert(Entry{EventID: "e1", DeviceID: devA, RevokedAt: t0}); added {
		t.Error("duplicate event id must not be added")
	}
	if added, _ := c.Upsert(Entry{EventID: "crl:abc", Serial: "abc", RevokedAt: t0, Source: SourceCRL}); added {
		t.Error("serial-only entry for a known serial must not be added")
	}
	if added, _ := c.Upsert(Entry{EventID: "crl:def", Serial: "def", RevokedAt: t0.Add(-time.Hour), Source: SourceCRL}); !added {
		t.Error("new serial-only entry should be added")
	}
	if added, _ := c.Upsert(Entry{EventID: "e2", Serial: "def", DeviceID: devB, RevokedAt: t0.Add(time.Hour)}); !added {
		t.Error("event naming a device for a CRL-known serial should be added")
	}
	if !c.IsRevokedDevice(devB) {
		t.Error("devB should be revoked")
	}
	if c.Len() != 3 {
		t.Errorf("Len = %d, want 3", c.Len())
	}
	e, ok := c.Get("e1")
	if !ok || !e.AppliedAt.Equal(fixedNow()) || e.Source != SourceEvent || e.Serial != "abc" {
		t.Errorf("Get(e1) = %+v, %v", e, ok)
	}
	if _, ok := c.Get("nope"); ok {
		t.Error("Get(nope) should be false")
	}
	got := c.Entries()
	if len(got) != 3 || got[0].EventID != "crl:def" || got[1].EventID != "e1" || got[2].EventID != "e2" {
		t.Errorf("Entries order = %v", []string{got[0].EventID, got[1].EventID, got[2].EventID})
	}
}

func TestEntriesTieBreakOnEventID(t *testing.T) {
	c := NewCache("", fixedNow)
	_, _ = c.Upsert(Entry{EventID: "b", DeviceID: devA, RevokedAt: t0})
	_, _ = c.Upsert(Entry{EventID: "a", DeviceID: devB, RevokedAt: t0})
	got := c.Entries()
	if got[0].EventID != "a" || got[1].EventID != "b" {
		t.Errorf("tie-break order = %s,%s", got[0].EventID, got[1].EventID)
	}
}

func TestUpsertValidation(t *testing.T) {
	c := NewCache("", fixedNow)
	if _, err := c.Upsert(Entry{DeviceID: devA, RevokedAt: t0}); err == nil {
		t.Error("missing event id should fail")
	}
	if _, err := c.Upsert(Entry{EventID: "x", RevokedAt: t0}); err == nil {
		t.Error("missing device and serial should fail")
	}
	if _, err := c.Upsert(Entry{EventID: "x", Serial: "zz", RevokedAt: t0}); err == nil {
		t.Error("non-hex serial without device should fail")
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

func TestMarkKickedAndUnkicked(t *testing.T) {
	c := NewCache("", fixedNow)
	_, _ = c.Upsert(Entry{EventID: "e2", DeviceID: devB, RevokedAt: t0.Add(time.Second)})
	_, _ = c.Upsert(Entry{EventID: "e1", DeviceID: devA, RevokedAt: t0})
	_, _ = c.Upsert(Entry{EventID: "crl:1", Serial: "1", RevokedAt: t0, Source: SourceCRL})

	un := c.Unkicked()
	if len(un) != 2 || un[0].EventID != "e1" || un[1].EventID != "e2" {
		t.Fatalf("Unkicked = %+v", un)
	}
	if err := c.MarkKicked("e1"); err != nil {
		t.Fatal(err)
	}
	e, _ := c.Get("e1")
	if !e.Kicked || e.KickedAt == nil || !e.KickedAt.Equal(fixedNow()) {
		t.Errorf("entry after MarkKicked = %+v", e)
	}
	if err := c.MarkKicked("e1"); err != nil {
		t.Errorf("second MarkKicked should be a no-op, got %v", err)
	}
	if err := c.MarkKicked("missing"); err == nil {
		t.Error("MarkKicked(missing) should fail")
	}
	if un := c.Unkicked(); len(un) != 1 || un[0].EventID != "e2" {
		t.Errorf("Unkicked after kick = %+v", un)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", SnapshotName)
	c := NewCache(path, fixedNow)
	if c.Path() != path {
		t.Fatalf("Path = %q", c.Path())
	}
	if _, err := c.Upsert(Entry{EventID: "e1", Serial: "0abc", DeviceID: devA, TenantID: tenant, Reason: "keyCompromise", RevokedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Upsert(Entry{EventID: "crl:def", Serial: "def", RevokedAt: t0.Add(time.Second), Source: SourceCRL}); err != nil {
		t.Fatal(err)
	}
	if err := c.MarkKicked("e1"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot is not JSON: %v", err)
	}
	if snap.Format != snapshotFormat || len(snap.Entries) != 2 || !snap.SavedAt.Equal(fixedNow()) {
		t.Errorf("snapshot = %+v", snap)
	}

	restored := NewCache(path, fixedNow)
	n, err := restored.Load()
	if err != nil || n != 2 {
		t.Fatalf("Load = %d, %v", n, err)
	}
	if !restored.IsRevokedDevice(devA) || !restored.IsRevokedSerial("ABC") || !restored.IsRevokedSerial("def") {
		t.Error("restored lookups failed")
	}
	e, ok := restored.Get("e1")
	if !ok || !e.Kicked || e.KickedAt == nil || e.TenantID != tenant || e.Reason != "keyCompromise" || !e.RevokedAt.Equal(t0) {
		t.Errorf("restored entry = %+v", e)
	}
	if n, err := restored.Load(); err != nil || n != 0 {
		t.Errorf("second Load = %d, %v; want 0 (duplicates skipped)", n, err)
	}
	if len(restored.Unkicked()) != 0 {
		t.Error("kicked flag should survive restart")
	}
}

func TestLoadEdgeCases(t *testing.T) {
	if n, err := NewCache("", fixedNow).Load(); err != nil || n != 0 {
		t.Errorf("Load without persistence = %d, %v", n, err)
	}
	missing := filepath.Join(t.TempDir(), "none.json")
	if n, err := NewCache(missing, fixedNow).Load(); err != nil || n != 0 {
		t.Errorf("Load missing = %d, %v", n, err)
	}
	corrupt := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(corrupt, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCache(corrupt, fixedNow).Load(); err == nil {
		t.Error("corrupt snapshot should fail")
	}
	partial := filepath.Join(t.TempDir(), "partial.json")
	snap := snapshot{Format: 1, Entries: []Entry{
		{EventID: "", DeviceID: devA, RevokedAt: t0},
		{EventID: "no-ids", RevokedAt: t0},
		{EventID: "ok", Serial: "0X0ABC", RevokedAt: t0},
		{EventID: "ok", Serial: "abc", RevokedAt: t0},
	}}
	raw, _ := json.Marshal(snap)
	if err := os.WriteFile(partial, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewCache(partial, fixedNow)
	if n, err := c.Load(); err != nil || n != 1 {
		t.Errorf("Load partial = %d, %v; want 1", n, err)
	}
	if !c.IsRevokedSerial("abc") {
		t.Error("serial from snapshot should be normalised and indexed")
	}
	unreadable := t.TempDir() // a directory, not a file
	if _, err := NewCache(unreadable, fixedNow).Load(); err == nil {
		t.Error("reading a directory should fail")
	}
}

func TestPersistFailureKeepsMemoryState(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewCache(filepath.Join(parent, SnapshotName), fixedNow)
	added, err := c.Upsert(Entry{EventID: "e1", DeviceID: devA, RevokedAt: t0})
	if !added {
		t.Fatal("entry should be added in memory even when persistence fails")
	}
	if err == nil {
		t.Fatal("expected persistence error")
	}
	if !c.IsRevokedDevice(devA) {
		t.Error("deny decision must not depend on disk")
	}
	if err := c.MarkKicked("e1"); err == nil {
		t.Error("MarkKicked should surface the persistence error")
	}
}
