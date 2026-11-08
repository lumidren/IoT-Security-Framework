package mgmt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// Page is the API_CONTRACT.md section 0 pagination envelope.
type Page struct {
	Items      any     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// ErrBadCursor is returned for cursors that were not produced by this service.
var ErrBadCursor = errors.New("cursor is not valid")

func parseLimit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxLimit {
		return 0, fmt.Errorf("limit must be an integer between 1 and %d", maxLimit)
	}
	return n, nil
}

func encodeCursor(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeCursor(s string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ErrBadCursor
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return ErrBadCursor
	}
	return nil
}
