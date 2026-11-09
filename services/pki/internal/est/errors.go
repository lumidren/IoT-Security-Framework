package est

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// httpError is an RFC 7030 style error response: an HTTP status with a
// text/plain explanation.
type httpError struct {
	status int
	msg    string
	cause  error
	// retryAfter, when positive, is sent as Retry-After (seconds).
	retryAfter time.Duration
}

func (e *httpError) Error() string {
	if e.cause != nil {
		return e.msg + ": " + e.cause.Error()
	}
	return e.msg
}

func errBadRequest(msg string, cause error) *httpError {
	return &httpError{status: http.StatusBadRequest, msg: msg, cause: cause}
}

func errUnauthorized(msg string) *httpError {
	return &httpError{status: http.StatusUnauthorized, msg: msg}
}

func errForbidden(msg string) *httpError {
	return &httpError{status: http.StatusForbidden, msg: msg}
}

func errUnsupportedMedia(msg string) *httpError {
	return &httpError{status: http.StatusUnsupportedMediaType, msg: msg}
}

func errInternal(msg string, cause error) *httpError {
	return &httpError{status: http.StatusInternalServerError, msg: msg, cause: cause}
}

func errUnavailable(msg string, cause error) *httpError {
	return &httpError{status: http.StatusServiceUnavailable, msg: msg, cause: cause}
}

// decodeBase64 decodes RFC 7030 base64 bodies leniently: whitespace and line
// breaks are ignored and both standard and URL alphabets, padded or not, are
// accepted.
func decodeBase64(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if clean == "" {
		return nil, errors.New("empty base64 body")
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	var lastErr error
	for _, enc := range encodings {
		b, err := enc.DecodeString(clean)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// encodeBase64Lines produces RFC 2045 style base64 with 76-character lines.
func encodeBase64Lines(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var sb strings.Builder
	for len(s) > 76 {
		sb.WriteString(s[:76])
		sb.WriteByte('\n')
		s = s[76:]
	}
	sb.WriteString(s)
	sb.WriteByte('\n')
	return sb.String()
}
