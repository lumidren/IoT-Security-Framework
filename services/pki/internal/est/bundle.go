package est

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/attest"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

// BundleKeyID is the kid carried in the bundle's protected header.
const BundleKeyID = "pki-bundle"

// Bundle is the trust bundle returned in X-IronMesh-Bundle (contract §3 step 6):
//
//	{1: tenant_cmd_pubkey, 2: fw_signing_pubkeys, 3: broker_host, 4: broker_port, 5: ca_pins}
type Bundle struct {
	TenantCmdPubKey  []byte   `cbor:"1,keyasint"`
	FwSigningPubKeys [][]byte `cbor:"2,keyasint"`
	BrokerHost       string   `cbor:"3,keyasint"`
	BrokerPort       int      `cbor:"4,keyasint"`
	CAPins           [][]byte `cbor:"5,keyasint"`
}

// Bundler signs trust bundles with the PKI's Ed25519 bundle key.
type Bundler struct {
	signer     cose.Signer
	brokerHost string
	brokerPort int
	pins       [][]byte
}

// NewBundler returns a Bundler. pins are SHA-256 SPKI hashes devices must pin
// (the Services CA per contract §4, plus the root).
func NewBundler(key ed25519.PrivateKey, brokerHost string, brokerPort int, pins [][]byte) (*Bundler, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("bundle: Ed25519 private key required")
	}
	if brokerHost == "" || brokerPort <= 0 || brokerPort > 65535 {
		return nil, errors.New("bundle: broker host and port are required")
	}
	for _, p := range pins {
		if len(p) != 32 {
			return nil, errors.New("bundle: CA pins must be 32-byte SHA-256 digests")
		}
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, key)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	return &Bundler{signer: signer, brokerHost: brokerHost, brokerPort: brokerPort, pins: pins}, nil
}

// Build returns the COSE_Sign1 bundle for a tenant.
func (b *Bundler) Build(p *store.TenantPolicy) ([]byte, error) {
	bundle := Bundle{
		TenantCmdPubKey:  p.TenantCmdPubKey,
		FwSigningPubKeys: p.FwSigningPubKeys,
		BrokerHost:       b.brokerHost,
		BrokerPort:       b.brokerPort,
		CAPins:           b.pins,
	}
	if len(bundle.TenantCmdPubKey) != 0 && len(bundle.TenantCmdPubKey) != ed25519.PublicKeySize {
		return nil, errors.New("bundle: tenant command public key must be 32 bytes")
	}
	if bundle.TenantCmdPubKey == nil {
		bundle.TenantCmdPubKey = []byte{}
	}
	if bundle.FwSigningPubKeys == nil {
		bundle.FwSigningPubKeys = [][]byte{}
	}
	if p.BrokerHost != "" {
		bundle.BrokerHost = p.BrokerHost
	}
	if p.BrokerPort > 0 {
		bundle.BrokerPort = p.BrokerPort
	}
	payload, err := attest.EncMode().Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("bundle: encode: %w", err)
	}
	headers := cose.Headers{Protected: cose.ProtectedHeader{
		cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA,
		cose.HeaderLabelKeyID:     []byte(BundleKeyID),
	}}
	msg, err := cose.Sign1(rand.Reader, b.signer, headers, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("bundle: sign: %w", err)
	}
	return msg, nil
}

// BuildHeader returns the base64 header value for a tenant.
func (b *Bundler) BuildHeader(p *store.TenantPolicy) (string, error) {
	raw, err := b.Build(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// VerifyBundle checks the signature with the PKI bundle public key and decodes
// the payload. Devices do the equivalent with the key baked into firmware.
func VerifyBundle(raw []byte, pub ed25519.PublicKey) (*Bundle, error) {
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(raw); err != nil {
		return nil, fmt.Errorf("bundle: invalid COSE_Sign1: %w", err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, pub)
	if err != nil {
		return nil, err
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("bundle: signature invalid: %w", err)
	}
	var b Bundle
	if err := attest.DecMode().Unmarshal(msg.Payload, &b); err != nil {
		return nil, fmt.Errorf("bundle: decode payload: %w", err)
	}
	return &b, nil
}
