package problem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	Write(rec, req, http.StatusForbidden, "role viewer is below admin", "role")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentType {
		t.Fatalf("content-type = %q", ct)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != "about:blank" || p.Title != "Forbidden" || p.Status != 403 || p.Detail != "role viewer is below admin" || p.Instance != "/v1/policy" {
		t.Errorf("unexpected problem %+v", p)
	}
	if len(p.Errors) != 1 || p.Errors[0] != "role" {
		t.Errorf("errors = %v", p.Errors)
	}
}

func TestWriteWithoutRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, nil, http.StatusUnauthorized, "nope")
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Instance != "" || p.Status != 401 || len(p.Errors) != 0 {
		t.Errorf("unexpected problem %+v", p)
	}
}
