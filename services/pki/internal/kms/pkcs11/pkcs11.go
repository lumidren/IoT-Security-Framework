//go:build pkcs11

// Package pkcs11 implements the kms.Provider and kms.Signer interfaces on top
// of a PKCS#11 token such as SoftHSM2 or a network HSM.
//
// It is compiled only with `-tags pkcs11` because github.com/miekg/pkcs11 needs
// cgo and the PKCS#11 headers. Without the tag the package exposes the same
// API but New returns kms.ErrUnavailable (see stub.go).
//
// Keys are addressed by their CKA_LABEL. Generate creates a token-resident,
// sensitive, non-extractable EC key pair with CKM_EC_KEY_PAIR_GEN; Sign uses
// CKM_ECDSA over the caller-supplied digest and converts the raw r||s output
// to the ASN.1 DER form expected by crypto/x509.
//
// SoftHSM2 quick start (used by the integration test, which skips unless
// SOFTHSM2_CONF is set):
//
//	softhsm2-util --init-token --free --label ironmesh --pin 1234 --so-pin 0000
//	export SOFTHSM2_CONF=/etc/softhsm2.conf PKI_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
//	export PKI_PKCS11_TOKEN=ironmesh PKI_PKCS11_PIN=1234
//	go test -tags pkcs11 ./internal/kms/pkcs11/
package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	p11 "github.com/miekg/pkcs11"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/kms"
)

// Config locates the PKCS#11 module and token.
type Config struct {
	// ModulePath is the path to the PKCS#11 shared library (e.g. libsofthsm2.so).
	ModulePath string
	// TokenLabel selects the token; the first token is used when empty.
	TokenLabel string
	// PIN is the user PIN.
	PIN string
}

var (
	oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// Provider is a logged-in PKCS#11 session.
type Provider struct {
	ctx     *p11.Ctx
	session p11.SessionHandle
	mu      sync.Mutex
}

// New loads the module, opens a session on the selected token and logs in.
func New(cfg Config) (kms.Provider, error) {
	if cfg.ModulePath == "" {
		return nil, errors.New("pkcs11: module path is required")
	}
	ctx := p11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: cannot load module %s", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11: initialize: %w", err)
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: list slots: %w", err)
	}
	var slot uint
	found := false
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if cfg.TokenLabel == "" || info.Label == cfg.TokenLabel {
			slot, found = s, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("pkcs11: token %q not found", cfg.TokenLabel)
	}
	session, err := ctx.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: open session: %w", err)
	}
	if err := ctx.Login(session, p11.CKU_USER, cfg.PIN); err != nil {
		var pe p11.Error
		if !errors.As(err, &pe) || pe != p11.CKR_USER_ALREADY_LOGGED_IN {
			return nil, fmt.Errorf("pkcs11: login: %w", err)
		}
	}
	return &Provider{ctx: ctx, session: session}, nil
}

// Close logs out and releases the module.
func (p *Provider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.ctx.Logout(p.session)
	_ = p.ctx.CloseSession(p.session)
	err := p.ctx.Finalize()
	p.ctx.Destroy()
	return err
}

// Generate creates a token-resident EC key pair labelled ref.
func (p *Provider) Generate(_ context.Context, ref string, alg kms.Algorithm) (kms.Signer, error) {
	var oid asn1.ObjectIdentifier
	switch alg {
	case kms.AlgorithmP256:
		oid = oidP256
	case kms.AlgorithmP384:
		oid = oidP384
	default:
		return nil, fmt.Errorf("pkcs11: algorithm %s is not supported by this backend", alg)
	}
	params, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	id := []byte(ref)
	pubTmpl := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PUBLIC_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_VERIFY, true),
		p11.NewAttribute(p11.CKA_EC_PARAMS, params),
		p11.NewAttribute(p11.CKA_LABEL, ref),
		p11.NewAttribute(p11.CKA_ID, id),
	}
	privTmpl := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_EC),
		p11.NewAttribute(p11.CKA_TOKEN, true),
		p11.NewAttribute(p11.CKA_PRIVATE, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_SIGN, true),
		p11.NewAttribute(p11.CKA_LABEL, ref),
		p11.NewAttribute(p11.CKA_ID, id),
	}
	p.mu.Lock()
	_, _, err = p.ctx.GenerateKeyPair(p.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_EC_KEY_PAIR_GEN, nil)}, pubTmpl, privTmpl)
	p.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("pkcs11: generate key pair: %w", err)
	}
	return p.Open(context.Background(), ref)
}

// Open locates the key pair labelled ref.
func (p *Provider) Open(_ context.Context, ref string) (kms.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	priv, err := p.findObject(p11.CKO_PRIVATE_KEY, ref)
	if err != nil {
		return nil, err
	}
	pubObj, err := p.findObject(p11.CKO_PUBLIC_KEY, ref)
	if err != nil {
		return nil, err
	}
	attrs, err := p.ctx.GetAttributeValue(p.session, pubObj, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_EC_PARAMS, nil),
		p11.NewAttribute(p11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11: read public key attributes: %w", err)
	}
	var params, point []byte
	for _, a := range attrs {
		switch a.Type {
		case p11.CKA_EC_PARAMS:
			params = a.Value
		case p11.CKA_EC_POINT:
			point = a.Value
		}
	}
	pub, err := parseECPublicKey(params, point)
	if err != nil {
		return nil, err
	}
	alg, err := kms.AlgorithmOf(pub)
	if err != nil {
		return nil, err
	}
	return &Signer{provider: p, handle: priv, pub: pub, alg: alg, label: ref}, nil
}

func (p *Provider) findObject(class uint, label string) (p11.ObjectHandle, error) {
	tmpl := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, class),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	if err := p.ctx.FindObjectsInit(p.session, tmpl); err != nil {
		return 0, fmt.Errorf("pkcs11: find init: %w", err)
	}
	objs, _, err := p.ctx.FindObjects(p.session, 1)
	_ = p.ctx.FindObjectsFinal(p.session)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: find objects: %w", err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("pkcs11: no object with label %q (class %d)", label, class)
	}
	return objs[0], nil
}

func parseECPublicKey(params, point []byte) (*ecdsa.PublicKey, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil {
		return nil, fmt.Errorf("pkcs11: parse CKA_EC_PARAMS: %w", err)
	}
	var curve elliptic.Curve
	switch {
	case oid.Equal(oidP256):
		curve = elliptic.P256()
	case oid.Equal(oidP384):
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("pkcs11: unsupported curve %v", oid)
	}
	// CKA_EC_POINT is a DER OCTET STRING wrapping the uncompressed point.
	var raw []byte
	if _, err := asn1.Unmarshal(point, &raw); err != nil {
		raw = point // some tokens return the bare point
	}
	x, y := elliptic.Unmarshal(curve, raw)
	if x == nil {
		return nil, errors.New("pkcs11: invalid EC point")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// Signer signs with a token-resident EC private key.
type Signer struct {
	provider *Provider
	handle   p11.ObjectHandle
	pub      *ecdsa.PublicKey
	alg      kms.Algorithm
	label    string
}

// Public implements crypto.Signer.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// KeyID implements kms.Signer.
func (s *Signer) KeyID() string { return "pkcs11:" + s.label }

// Sign implements crypto.Signer.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != s.alg.Hash() {
		return nil, fmt.Errorf("pkcs11: key %s requires %s digests", s.label, s.alg.Hash())
	}
	s.provider.mu.Lock()
	defer s.provider.mu.Unlock()
	if err := s.provider.ctx.SignInit(s.provider.session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_ECDSA, nil)}, s.handle); err != nil {
		return nil, fmt.Errorf("pkcs11: sign init: %w", err)
	}
	raw, err := s.provider.ctx.Sign(s.provider.session, digest)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: sign: %w", err)
	}
	if len(raw)%2 != 0 {
		return nil, errors.New("pkcs11: malformed raw ECDSA signature")
	}
	half := len(raw) / 2
	sig := struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:half]), new(big.Int).SetBytes(raw[half:])}
	der, err := asn1.Marshal(sig)
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(s.pub, digest, der) {
		return nil, errors.New("pkcs11: signature does not verify against the token public key")
	}
	return der, nil
}
