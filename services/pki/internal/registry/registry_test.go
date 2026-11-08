package registry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
