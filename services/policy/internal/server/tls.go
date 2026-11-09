package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
)

// TLSConfig returns the optional TLS listener configuration (POLICY_TLS_CERT_FILE /
// POLICY_TLS_KEY_FILE): TLS 1.3 only, and client certificates are optional but, when presented,
// must chain to clientCAs (the Services CA). The management API then binds service JWTs to the
// presented certificate (THREAT_MODEL T-50). A nil clientCAs requests no client certificates.
func TLSConfig(certFile, keyFile string, clientCAs *x509.CertPool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls listener: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	if clientCAs != nil {
		cfg.ClientCAs = clientCAs
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}

// Listen opens addr, wrapped in TLS when cfg is non-nil. net/http fills Request.TLS for
// connections accepted from a TLS listener.
func Listen(addr string, cfg *tls.Config) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return ln, nil
	}
	return tls.NewListener(ln, cfg), nil
}
