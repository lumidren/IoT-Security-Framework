// Package problem writes RFC 9457 problem-details error responses (API_CONTRACT.md section 0).
package problem

import (
	"encoding/json"
	"net/http"
)

// ContentType is the media type of a problem-details response.
const ContentType = "application/problem+json"

// Problem is an RFC 9457 problem details document.
type Problem struct {
	Type     string   `json:"type"`
	Title    string   `json:"title"`
	Status   int      `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	Instance string   `json:"instance,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

// New builds a Problem for status with the standard title.
func New(status int, detail string, errs ...string) Problem {
	return Problem{
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
		Errors: errs,
	}
}

// Write encodes a Problem for status to w, using the request path as instance.
func Write(w http.ResponseWriter, r *http.Request, status int, detail string, errs ...string) {
	p := New(status, detail, errs...)
	if r != nil && r.URL != nil {
		p.Instance = r.URL.Path
	}
	p.Write(w)
}

// Write encodes p to w.
func (p Problem) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}
