package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const tenant = "7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"

func TestStates(t *testing.T) {
	t.Parallel()
	allowed := map[State]bool{StateManufactured: true, StateProvisioned: true, StateActive: true, StateQuarantined: false, StateDecommissioned: false, State("weird"): false}
	for s, want := range allowed {
		if s.EnrollmentAllowed() != want {
			t.Errorf("%s: allowed=%v", s, !want)
		}
	}
}

func TestMemory(t *testing.T) {
	t.Parallel()
	m := NewMemory()
	ctx := context.Background()
	if _, err := m.GetDevice(ctx, tenant, "dev-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := m.RecordAssurance(ctx, tenant, "dev-1", "hardware"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("record missing: %v", err)
	}
	m.Put(Device{DeviceID: "dev-1", TenantID: tenant, State: StateManufactured})
	m.SetState(tenant, "dev-1", StateActive)
	m.SetState(tenant, "dev-unknown", StateActive)
	if err := m.RecordAssurance(ctx, tenant, "dev-1", "software"); err != nil {
		t.Fatal(err)
	}
	d, err := m.GetDevice(ctx, tenant, "dev-1")
	if err != nil || d.State != StateActive || d.Assurance != "software" {
		t.Fatalf("device %+v %v", d, err)
	}
	m.Err = errors.New("down")
	if _, err := m.GetDevice(ctx, tenant, "dev-1"); err == nil {
		t.Fatal("expected outage error")
	}
	if err := m.RecordAssurance(ctx, tenant, "dev-1", "x"); err == nil {
		t.Fatal("expected outage error")
	}
	if d, err := (AllowAll{}).GetDevice(ctx, tenant, "dev-9"); err != nil || d.State != StateActive || d.DeviceID != "dev-9" {
		t.Fatalf("AllowAll %+v %v", d, err)
	}
	if err := (AllowAll{}).RecordAssurance(ctx, tenant, "dev-9", "x"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClient(t *testing.T) {
	t.Parallel()
	var lastAuth, lastPath, lastMethod, lastBody string
	status := http.StatusOK
	body := `{"device_id":"dev-8f3a1c2b9d4e5f60","tenant_id":"` + tenant + `","state":"provisioned","assurance_level":"hardware"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth, lastPath, lastMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		lastBody = string(buf[:n])
		w.WriteHeader(status)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(body))
		}
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL+"/", "tok", nil)
	ctx := context.Background()

	d, err := c.GetDevice(ctx, tenant, "dev-8f3a1c2b9d4e5f60")
	if err != nil || d.State != StateProvisioned || d.Assurance != "hardware" {
		t.Fatalf("GetDevice: %+v %v", d, err)
	}
	if lastAuth != "Bearer tok" || lastPath != "/internal/v1/tenants/"+tenant+"/devices/dev-8f3a1c2b9d4e5f60" {
		t.Fatalf("request %s %s", lastAuth, lastPath)
	}
	if err := c.RecordAssurance(ctx, tenant, "dev-8f3a1c2b9d4e5f60", "software"); err != nil {
		t.Fatal(err)
	}
	if lastMethod != http.MethodPost || lastPath != "/internal/v1/tenants/"+tenant+"/devices/dev-8f3a1c2b9d4e5f60/assurance" || lastBody != `{"assurance_level":"software"}` {
		t.Fatalf("assurance request %s %s %s", lastMethod, lastPath, lastBody)
	}
	// Missing ids are filled from the request; missing state is an error.
	body = `{"state":"active"}`
	if d, err := c.GetDevice(ctx, tenant, "dev-x"); err != nil || d.DeviceID != "dev-x" || d.TenantID != tenant {
		t.Fatalf("filled ids: %+v %v", d, err)
	}
	body = `{"device_id":"dev-x"}`
	if _, err := c.GetDevice(ctx, tenant, "dev-x"); err == nil {
		t.Fatal("missing state accepted")
	}
	body = `not json`
	if _, err := c.GetDevice(ctx, tenant, "dev-x"); err == nil {
		t.Fatal("bad json accepted")
	}
	status = http.StatusNotFound
	if _, err := c.GetDevice(ctx, tenant, "dev-x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %v", err)
	}
	if err := c.RecordAssurance(ctx, tenant, "dev-x", "hardware"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404 assurance: %v", err)
	}
	status = http.StatusInternalServerError
	if _, err := c.GetDevice(ctx, tenant, "dev-x"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("500: %v", err)
	}
	if err := c.RecordAssurance(ctx, tenant, "dev-x", "hardware"); err == nil {
		t.Fatal("500 assurance accepted")
	}
	// Transport failure.
	down := NewHTTPClient("http://127.0.0.1:1", "", nil)
	if _, err := down.GetDevice(ctx, tenant, "dev-x"); err == nil {
		t.Fatal("expected transport error")
	}
	if err := down.RecordAssurance(ctx, tenant, "dev-x", "hardware"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestMemoryRecordEnrollment(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemory()
	e := Enrollment{SerialHex: "ab", SeType: "tpm2", AssuranceLevel: "hardware"}
	if err := m.RecordEnrollment(ctx, tenant, "dev-1", e); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
	m.Put(Device{DeviceID: "dev-1", TenantID: tenant, State: StateManufactured})
	if err := m.RecordEnrollment(ctx, tenant, "dev-1", e); err != nil {
		t.Fatal(err)
	}
	d, _ := m.GetDevice(ctx, tenant, "dev-1")
	if d.State != StateActive || d.Assurance != "hardware" {
		t.Fatalf("device %+v", d)
	}
	// Quarantined devices are not reactivated by an enrollment record.
	m.SetState(tenant, "dev-1", StateQuarantined)
	if err := m.RecordEnrollment(ctx, tenant, "dev-1", e); err != nil {
		t.Fatal(err)
	}
	if d, _ := m.GetDevice(ctx, tenant, "dev-1"); d.State != StateQuarantined {
		t.Fatalf("state %q", d.State)
	}
	if got := m.Enrollments(tenant, "dev-1"); len(got) != 2 || got[0] != e {
		t.Fatalf("enrollments %+v", got)
	}
	boom := errors.New("boom")
	m.SetEnrollFailure(boom, 2)
	for i := 0; i < 2; i++ {
		if err := m.RecordEnrollment(ctx, tenant, "dev-1", e); !errors.Is(err, boom) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	if err := m.RecordEnrollment(ctx, tenant, "dev-1", e); err != nil {
		t.Fatalf("after failures: %v", err)
	}
	m.SetEnrollFailure(boom, 0)
	for i := 0; i < 3; i++ {
		if err := m.RecordEnrollment(ctx, tenant, "dev-1", e); !errors.Is(err, boom) {
			t.Fatalf("permanent failure %d: %v", i, err)
		}
	}
	m.SetEnrollFailure(nil, 0)
	m.Err = errors.New("outage")
	if err := m.RecordEnrollment(ctx, tenant, "dev-1", e); err == nil {
		t.Fatal("outage ignored")
	}
	if m.EnrollCalls() != 10 {
		t.Fatalf("calls %d", m.EnrollCalls())
	}
	var zero Memory // zero value usable
	zero.devices = map[string]Device{key(tenant, "dev-2"): {DeviceID: "dev-2", TenantID: tenant, State: StateProvisioned}}
	if err := zero.RecordEnrollment(ctx, tenant, "dev-2", e); err != nil {
		t.Fatal(err)
	}
	if err := (AllowAll{}).RecordEnrollment(ctx, tenant, "dev-9", e); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRecordEnrollment(t *testing.T) {
	t.Parallel()
	var gotPath, gotAuth, gotType string
	var gotBody map[string]any
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotType = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"id":"dev-8f3a1c2b9d4e5f60","state":"active"}`))
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL, "pki-token", nil)
	ctx := context.Background()
	nb := time.Date(2026, 11, 9, 10, 0, 0, 0, time.FixedZone("x", 3600))
	e := Enrollment{SerialHex: "00ff", NotBefore: nb, NotAfter: nb.Add(336 * time.Hour), SeType: "atecc608", AssuranceLevel: "hardware", FwVersion: "2.4.1", FwHashHex: strings.Repeat("ab", 32)}
	if err := c.RecordEnrollment(ctx, tenant, "dev-8f3a1c2b9d4e5f60", e); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/internal/v1/devices/dev-8f3a1c2b9d4e5f60/enrolled" || gotAuth != "Bearer pki-token" || gotType != "application/json" {
		t.Fatalf("request %s %s %s", gotPath, gotAuth, gotType)
	}
	want := map[string]any{
		"serial_hex": "00ff", "not_before": "2026-11-09T09:00:00Z", "not_after": "2026-11-23T09:00:00Z",
		"se_type": "atecc608", "assurance_level": "hardware", "fw_version": "2.4.1", "fw_hash_hex": strings.Repeat("ab", 32),
	}
	if len(gotBody) != len(want) {
		t.Fatalf("body %v", gotBody)
	}
	for k, v := range want {
		if gotBody[k] != v {
			t.Fatalf("body[%s] = %v want %v", k, gotBody[k], v)
		}
	}
	// Empty firmware fields are omitted (the registry accepts null).
	if err := c.RecordEnrollment(ctx, tenant, "dev-x", Enrollment{SerialHex: "01", SeType: "software", AssuranceLevel: "software"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := gotBody["fw_hash_hex"]; ok {
		t.Fatalf("empty fw_hash_hex sent: %v", gotBody)
	}
	for code, check := range map[int]func(error) bool{
		http.StatusNoContent:           func(err error) bool { return err == nil },
		http.StatusNotFound:            func(err error) bool { return errors.Is(err, ErrNotFound) },
		http.StatusUnprocessableEntity: func(err error) bool { return errors.Is(err, ErrRejected) },
		http.StatusConflict:            func(err error) bool { return errors.Is(err, ErrRejected) },
		http.StatusTooManyRequests:     func(err error) bool { return err != nil && !errors.Is(err, ErrRejected) },
		http.StatusRequestTimeout:      func(err error) bool { return err != nil && !errors.Is(err, ErrRejected) },
		http.StatusBadGateway: func(err error) bool {
			return err != nil && !errors.Is(err, ErrRejected) && !errors.Is(err, ErrNotFound)
		},
	} {
		status = code
		if err := c.RecordEnrollment(ctx, tenant, "dev-x", e); !check(err) {
			t.Errorf("status %d: %v", code, err)
		}
	}
	down := NewHTTPClient("http://127.0.0.1:1", "", nil)
	if err := down.RecordEnrollment(ctx, tenant, "dev-x", e); err == nil {
		t.Fatal("transport error ignored")
	}
	bad := NewHTTPClient("http://bad\x7f", "", nil)
	if err := bad.RecordEnrollment(ctx, tenant, "dev-x", e); err == nil {
		t.Fatal("bad URL accepted")
	}
}
