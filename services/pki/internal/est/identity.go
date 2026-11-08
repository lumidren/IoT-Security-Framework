package est

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/ca"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/registry"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// ClientIdentity is the authenticated device behind an mTLS connection.
type ClientIdentity struct {
	Cert *x509.Certificate
	ID   *ca.DeviceIdentity
	// Issuer is KindFactory for bootstrap certificates and KindDevice for
	// operational certificates.
	Issuer ca.Kind
}

// Identify extracts and validates the device identity from the TLS client
// certificate. The TLS layer has already verified the chain against the
// Factory and Device CAs; this adds profile validation and a revocation check.
func Identify(ctx context.Context, r *http.Request, factoryCA, deviceCA *x509.Certificate, st store.Store, now time.Time) (*ClientIdentity, *httpError) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errUnauthorized("TLS client certificate required")
	}
	if len(r.TLS.VerifiedChains) == 0 {
		return nil, errUnauthorized("TLS client certificate was not verified")
	}
	leaf := r.TLS.PeerCertificates[0]
	var issuer ca.Kind
	switch {
	case ca.IssuedBy(leaf, factoryCA):
		issuer = ca.KindFactory
	case ca.IssuedBy(leaf, deviceCA):
		issuer = ca.KindDevice
	default:
		return nil, errForbidden("client certificate was not issued by the Factory or Device CA")
	}
	id, err := ca.ParseDeviceIdentity(leaf)
	if err != nil {
		return nil, errForbidden("client certificate is not a valid device certificate: " + err.Error())
	}
	if (issuer == ca.KindFactory) != id.Bootstrap {
		return nil, errForbidden("client certificate OU markers do not match its issuer")
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errUnauthorized("client certificate is not within its validity period")
	}
	if _, err := st.GetRevocation(ctx, id.Serial); err == nil {
		return nil, errUnauthorized("client certificate has been revoked")
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, errUnavailable("revocation lookup failed", err)
	}
	return &ClientIdentity{Cert: leaf, ID: id, Issuer: issuer}, nil
}

// checkBootstrapSerialMatchesManufactureRecord enforces, on first enrollment,
// that the bootstrap certificate presented over TLS is exactly the one the
// Registry recorded at manufacture: a bootstrap certificate minted for the
// same device id by anyone else (or an older, replaced one) is refused.
// Renewals and devices without a recorded serial are not constrained.
func checkBootstrapSerialMatchesManufactureRecord(client *ClientIdentity, dev *registry.Device) *httpError {
	if client == nil || dev == nil || client.Issuer != ca.KindFactory || dev.BootstrapSerial == "" {
		return nil
	}
	_, recorded, err := ca.ParseSerial(dev.BootstrapSerial)
	if err != nil {
		return errForbidden("manufacture record carries an unparsable bootstrap serial")
	}
	if recorded != client.ID.Serial {
		return errForbidden("bootstrap certificate serial does not match the manufacture record")
	}
	return nil
}
