package ca

import (
	"fmt"
	"sort"
	"strings"
)

// RFC 5280 §5.3.1 CRLReason codes.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

var reasonNames = map[string]int{
	"unspecified":          ReasonUnspecified,
	"keycompromise":        ReasonKeyCompromise,
	"cacompromise":         ReasonCACompromise,
	"affiliationchanged":   ReasonAffiliationChanged,
	"superseded":           ReasonSuperseded,
	"cessationofoperation": ReasonCessationOfOperation,
	"certificatehold":      ReasonCertificateHold,
	"privilegewithdrawn":   ReasonPrivilegeWithdrawn,
	"aacompromise":         ReasonAACompromise,
}

var reasonStrings = map[int]string{
	ReasonUnspecified:          "unspecified",
	ReasonKeyCompromise:        "keyCompromise",
	ReasonCACompromise:         "cACompromise",
	ReasonAffiliationChanged:   "affiliationChanged",
	ReasonSuperseded:           "superseded",
	ReasonCessationOfOperation: "cessationOfOperation",
	ReasonCertificateHold:      "certificateHold",
	ReasonRemoveFromCRL:        "removeFromCRL",
	ReasonPrivilegeWithdrawn:   "privilegeWithdrawn",
	ReasonAACompromise:         "aACompromise",
}

// ParseReason converts a reason name (case-insensitive, e.g. "keyCompromise",
// "key_compromise") or numeric code into an RFC 5280 CRLReason. removeFromCRL
// (8) is not a revocation reason and is rejected.
func ParseReason(s string) (int, error) {
	norm := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.TrimSpace(s)))
	if norm == "" {
		return ReasonUnspecified, nil
	}
	if code, ok := reasonNames[norm]; ok {
		return code, nil
	}
	var code int
	if _, err := fmt.Sscanf(norm, "%d", &code); err == nil {
		if _, ok := reasonStrings[code]; ok && code != ReasonRemoveFromCRL {
			return code, nil
		}
	}
	return 0, fmt.Errorf("unknown revocation reason %q (valid: %s)", s, strings.Join(ReasonNames(), ", "))
}

// ReasonString returns the RFC 5280 name of a reason code.
func ReasonString(code int) string {
	if s, ok := reasonStrings[code]; ok {
		return s
	}
	return fmt.Sprintf("reason(%d)", code)
}

// ReasonNames lists the accepted reason names.
func ReasonNames() []string {
	out := make([]string, 0, len(reasonStrings))
	for code, name := range reasonStrings {
		if code == ReasonRemoveFromCRL {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
