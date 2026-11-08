package ca

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Identifier formats from DESIGN_CONTRACT §1.
var (
	tenantIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	deviceIDRe = regexp.MustCompile(`^dev-[0-9a-f]{16}$`)
)

// ValidateTenantID checks that s is a lower-case hyphenated UUIDv4.
func ValidateTenantID(s string) error {
	if !tenantIDRe.MatchString(s) {
		return fmt.Errorf("invalid tenant id %q: must be a lower-case UUIDv4", s)
	}
	return nil
}

// ValidateDeviceID checks that s is "dev-" followed by 16 lower-case hex chars.
func ValidateDeviceID(s string) error {
	if !deviceIDRe.MatchString(s) {
		return fmt.Errorf("invalid device id %q: must match dev-<16 lower-case hex>", s)
	}
	return nil
}

// DeviceURN returns the SAN URI "urn:ironmesh:tenant:<t>:device:<d>".
func DeviceURN(tenantID, deviceID string) *url.URL {
	return &url.URL{Scheme: "urn", Opaque: fmt.Sprintf("ironmesh:tenant:%s:device:%s", tenantID, deviceID)}
}

// ParseDeviceURN parses a device SAN URI back into its tenant and device ids.
func ParseDeviceURN(u *url.URL) (tenantID, deviceID string, err error) {
	if u == nil || u.Scheme != "urn" {
		return "", "", fmt.Errorf("not a urn: %v", u)
	}
	parts := strings.Split(u.Opaque, ":")
	if len(parts) != 5 || parts[0] != "ironmesh" || parts[1] != "tenant" || parts[3] != "device" {
		return "", "", fmt.Errorf("malformed ironmesh device urn %q", u.String())
	}
	if err := ValidateTenantID(parts[2]); err != nil {
		return "", "", err
	}
	if err := ValidateDeviceID(parts[4]); err != nil {
		return "", "", err
	}
	return parts[2], parts[4], nil
}
