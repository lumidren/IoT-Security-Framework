// Package identity encodes the IronMesh identity rules from DESIGN_CONTRACT.md sections 1, 2 and 4:
// device id format, tenant id format, the service identities allowed on the broker, and parsing of
// X.509 subject names as EMQX renders them.
package identity

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Kind classifies an authenticated MQTT client.
type Kind string

const (
	// KindDevice is a fleet device holding an operational certificate from the Device CA.
	KindDevice Kind = "device"
	// KindService is an IronMesh backend service holding a Services CA certificate.
	KindService Kind = "service"
)

const (
	// ServiceBridge is the CN of the bridge service certificate.
	ServiceBridge = "svc-bridge"
	// ServiceRegistry is the CN of the registry service certificate.
	ServiceRegistry = "svc-registry"
	// Organization is the mandatory subject O of every IronMesh certificate.
	Organization = "IronMesh"
	// ServicesOU is the subject OU carried by service certificates.
	ServicesOU = "services"
	// BootstrapOUPrefix marks factory bootstrap certificates, which must never reach the broker.
	BootstrapOUPrefix = "bootstrap:"
	// AssuranceOUPrefix marks the assurance level (section 10), e.g. assurance:software.
	AssuranceOUPrefix = "assurance:"
)

var (
	deviceIDRe = regexp.MustCompile(`^dev-[0-9a-f]{16}$`)
	tenantIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// IsDeviceID reports whether s is a well-formed device id (dev- + 16 lower-case hex chars).
func IsDeviceID(s string) bool { return deviceIDRe.MatchString(s) }

// IsTenantID reports whether s is a lower-case hyphenated UUID.
func IsTenantID(s string) bool { return tenantIDRe.MatchString(s) }

// IsServiceCN reports whether cn names a service identity permitted on the broker.
func IsServiceCN(cn string) bool { return cn == ServiceBridge || cn == ServiceRegistry }

// DN is the subset of an X.509 subject the policy service reasons about.
type DN struct {
	CN string
	O  []string
	OU []string
}

var (
	// ErrEmptyDN is returned when the subject string is blank.
	ErrEmptyDN = errors.New("empty subject")
	// ErrNoTenant is returned when a device subject carries no tenant OU.
	ErrNoTenant = errors.New("subject carries no tenant OU")
	// ErrBootstrap is returned when a subject carries a bootstrap OU.
	ErrBootstrap = errors.New("bootstrap certificate is not valid for the broker")
	// ErrAmbiguousTenant is returned when more than one OU looks like a tenant id.
	ErrAmbiguousTenant = errors.New("subject carries more than one tenant OU")
)

// ParseDN parses a subject distinguished name as EMQX renders ${cert_subject}. Both the RFC 4514
// form ("CN=dev-...,OU=<tenant>,O=IronMesh", with \-escapes and optional quoting) and the OpenSSL
// one-line form ("/O=IronMesh/OU=<tenant>/CN=dev-...") are accepted. Attribute order is irrelevant.
func ParseDN(s string) (DN, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DN{}, ErrEmptyDN
	}
	var parts []string
	var err error
	if strings.HasPrefix(s, "/") {
		parts, err = splitUnescaped(s[1:], "/")
	} else {
		parts, err = splitUnescaped(s, ",+;")
	}
	if err != nil {
		return DN{}, err
	}
	var dn DN
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return DN{}, fmt.Errorf("malformed subject %q: empty RDN", s)
		}
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			return DN{}, fmt.Errorf("malformed subject %q: RDN %q has no attribute type", s, p)
		}
		key := strings.ToUpper(strings.TrimSpace(p[:eq]))
		val, err := unescape(strings.TrimSpace(p[eq+1:]))
		if err != nil {
			return DN{}, fmt.Errorf("malformed subject %q: %w", s, err)
		}
		switch key {
		case "CN", "2.5.4.3":
			if dn.CN != "" {
				return DN{}, fmt.Errorf("malformed subject %q: multiple CN attributes", s)
			}
			dn.CN = val
		case "O", "2.5.4.10":
			dn.O = append(dn.O, val)
		case "OU", "2.5.4.11":
			dn.OU = append(dn.OU, val)
		}
	}
	return dn, nil
}

// DNFromName converts a parsed certificate subject into a DN.
func DNFromName(n pkix.Name) DN {
	return DN{CN: n.CommonName, O: append([]string(nil), n.Organization...), OU: append([]string(nil), n.OrganizationalUnit...)}
}

// HasO reports whether the subject carries organization v.
func (d DN) HasO(v string) bool { return contains(d.O, v) }

// HasOU reports whether the subject carries organizational unit v.
func (d DN) HasOU(v string) bool { return contains(d.OU, v) }

// IsBootstrap reports whether any OU marks the certificate as a factory bootstrap certificate.
func (d DN) IsBootstrap() bool {
	for _, ou := range d.OU {
		if strings.HasPrefix(ou, BootstrapOUPrefix) {
			return true
		}
	}
	return false
}

// Tenant extracts the tenant id from the OU attributes of a device certificate (section 2:
// Subject OU = tenant id). Assurance markers (assurance:*) are ignored; a bootstrap marker is an
// error; exactly one UUID-shaped OU must exist.
func (d DN) Tenant() (string, error) {
	if d.IsBootstrap() {
		return "", ErrBootstrap
	}
	tenant := ""
	for _, ou := range d.OU {
		if IsTenantID(ou) {
			if tenant != "" {
				return "", ErrAmbiguousTenant
			}
			tenant = ou
		}
	}
	if tenant == "" {
		return "", ErrNoTenant
	}
	return tenant, nil
}

// Assurance returns the assurance marker (e.g. "software") if one is present, else "hardware"
// per section 10 (hardware is the default, carrying no marker).
func (d DN) Assurance() string {
	for _, ou := range d.OU {
		if strings.HasPrefix(ou, AssuranceOUPrefix) {
			return strings.TrimPrefix(ou, AssuranceOUPrefix)
		}
	}
	return "hardware"
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// splitUnescaped splits s on any byte in seps, ignoring separators that are backslash-escaped or
// inside double quotes. Escapes are preserved for unescape.
func splitUnescaped(s, seps string) ([]string, error) {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				return nil, fmt.Errorf("dangling escape in %q", s)
			}
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
		case c == '"':
			inQuote = !inQuote
			cur.WriteByte(c)
		case !inQuote && strings.IndexByte(seps, c) >= 0:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote in %q", s)
	}
	parts = append(parts, cur.String())
	return parts, nil
}

// unescape removes RFC 4514 escaping (\c and \XX) and surrounding double quotes from an attribute
// value.
func unescape(v string) (string, error) {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if !strings.ContainsRune(v, '\\') {
		return v, nil
	}
	var out strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		if i+1 >= len(v) {
			return "", fmt.Errorf("dangling escape in value %q", v)
		}
		next := v[i+1]
		if isHex(next) && i+2 < len(v) && isHex(v[i+2]) {
			b, err := strconv.ParseUint(v[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf("bad hex escape in %q", v)
			}
			out.WriteByte(byte(b))
			i += 2
			continue
		}
		out.WriteByte(next)
		i++
	}
	return out.String(), nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
