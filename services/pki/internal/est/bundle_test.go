package est_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/est"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func TestBundleRoundTrip(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins := [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}
	b, err := est.NewBundler(priv, "mqtt.example", 8883, pins)
	if err != nil {
		t.Fatal(err)
	}
	cmdKey := bytes.Repeat([]byte{7}, 32)
	policy := &store.TenantPolicy{TenantCmdPubKey: cmdKey, FwSigningPubKeys: [][]byte{bytes.Repeat([]byte{9}, 32)}}
	hdr, err := b.BuildHeader(policy)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(hdr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := est.VerifyBundle(raw, pub)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !bytes.Equal(got.TenantCmdPubKey, cmdKey) || len(got.FwSigningPubKeys) != 1 || got.BrokerHost != "mqtt.example" || got.BrokerPort != 8883 || len(got.CAPins) != 2 {
		t.Fatalf("bundle %+v", got)
	}
	// Tenant overrides for broker, empty keys tolerated.
	raw, err = b.Build(&store.TenantPolicy{BrokerHost: "tenant.mqtt", BrokerPort: 18883})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = est.VerifyBundle(raw, pub)
	if got.BrokerHost != "tenant.mqtt" || got.BrokerPort != 18883 || len(got.TenantCmdPubKey) != 0 || len(got.FwSigningPubKeys) != 0 {
		t.Fatalf("override bundle %+v", got)
	}
	// Wrong verification key and tampering fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := est.VerifyBundle(raw, otherPub); err == nil {
		t.Error("wrong key accepted")
	}
	raw[len(raw)-1] ^= 0xff
	if _, err := est.VerifyBundle(raw, pub); err == nil {
		t.Error("tampered bundle accepted")
	}
	if _, err := est.VerifyBundle([]byte("junk"), pub); err == nil {
		t.Error("junk accepted")
	}
	// Invalid tenant key length.
	if _, err := b.Build(&store.TenantPolicy{TenantCmdPubKey: []byte{1, 2}}); err == nil {
		t.Error("short tenant key accepted")
	}
}

func TestNewBundlerValidation(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		key  ed25519.PrivateKey
		host string
		port int
		pins [][]byte
	}{
		{"short key", priv[:10], "h", 1, nil},
		{"no host", priv, "", 1, nil},
		{"bad port", priv, "h", 70000, nil},
		{"bad pin", priv, "h", 1, [][]byte{{1}}},
	}
	for _, c := range cases {
		if _, err := est.NewBundler(c.key, c.host, c.port, c.pins); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}
