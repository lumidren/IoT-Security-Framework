package bridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kfake"
)

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func produceOnce(t *testing.T, cfg KafkaConfig) error {
	t.Helper()
	cfg.Logger, cfg.Linger, cfg.DeliveryTimeout = discardLogger(), -1, 2*time.Second
	p, err := NewKafkaProducer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(testCtx(t), 5*time.Second)
	defer cancel()
	return p.Produce(ctx, Record{Topic: "im.auth", Key: []byte("k"), Value: []byte("v")})
}

func TestKafkaSASLPlainAndScram(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, "im.auth"), kfake.EnableSASL(),
		kfake.Superuser("PLAIN", "plain-user", "plain-pass"), kfake.Superuser("SCRAM-SHA-512", "scram-user", "scram-pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	ctx := testCtx(t)
	for _, c := range []struct {
		mech, user, pass string
		ok               bool
	}{
		{SASLPlain, "plain-user", "plain-pass", true},
		{SASLScramSHA512, "scram-user", "scram-pass", true},
		{SASLScramSHA512, "scram-user", "wrong", false},
		{SASLPlain, "plain-user", "wrong", false},
	} {
		m, err := NewSASLMechanism(ctx, c.mech, c.user, c.pass, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = produceOnce(t, KafkaConfig{Brokers: cluster.ListenAddrs(), SASL: m})
		if (err == nil) != c.ok {
			t.Errorf("%s/%s/%s: err=%v want ok=%v", c.mech, c.user, c.pass, err, c.ok)
		}
	}
	// Without SASL the cluster refuses the client.
	if err := produceOnce(t, KafkaConfig{Brokers: cluster.ListenAddrs()}); err == nil {
		t.Error("unauthenticated produce succeeded")
	}
}

func selfSignedTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kafka"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, pool
}

func TestKafkaTLSWithSASL(t *testing.T) {
	serverTLS, pool := selfSignedTLS(t)
	cluster, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(1, "im.auth"), kfake.TLS(serverTLS),
		kfake.EnableSASL(), kfake.Superuser("PLAIN", "bridge", "pw"))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	m, _ := NewSASLMechanism(testCtx(t), "PLAIN", "bridge", "pw", nil)
	if err := produceOnce(t, KafkaConfig{Brokers: cluster.ListenAddrs(), SASL: m, TLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}); err != nil {
		t.Fatalf("TLS + SASL/PLAIN: %v", err)
	}
	// A client that does not trust the broker certificate fails.
	if err := produceOnce(t, KafkaConfig{Brokers: cluster.ListenAddrs(), SASL: m, TLS: &tls.Config{MinVersion: tls.VersionTLS12}}); err == nil {
		t.Error("untrusted broker certificate accepted")
	}
}

func TestEnsureTopics(t *testing.T) {
	cluster, err := kfake.NewCluster(kfake.NumBrokers(3), kfake.SeedTopics(1, "im.ingest"))
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	p, err := NewKafkaProducer(KafkaConfig{Brokers: cluster.ListenAddrs(), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx := testCtx(t)
	created, err := p.EnsureTopics(ctx, 12, 3, PlatformTopics...)
	if err != nil {
		t.Fatalf("EnsureTopics: %v", err)
	}
	sort.Strings(created)
	if strings.Join(created, ",") != "im.alerts,im.audit,im.auth,im.campaigns,im.commands" {
		t.Fatalf("created = %v (im.ingest already existed)", created)
	}
	adm := kadm.NewClient(p.cl)
	details, err := adm.ListTopics(ctx, "im.alerts", "im.campaigns")
	if err != nil {
		t.Fatal(err)
	}
	for _, td := range details {
		if len(td.Partitions) != 12 || td.Partitions.NumReplicas() != 3 {
			t.Errorf("%s: partitions=%d replicas=%d", td.Topic, len(td.Partitions), td.Partitions.NumReplicas())
		}
	}
	// Idempotent: already-existing topics are success.
	if created, err := p.EnsureTopics(ctx, 12, 3, PlatformTopics...); err != nil || len(created) != 0 {
		t.Fatalf("second run: %v %v", created, err)
	}
	// A replication factor above the broker count is a real error.
	if _, err := p.EnsureTopics(ctx, 1, 5, "im.extra"); err == nil {
		t.Fatal("impossible replication factor accepted")
	}
	if created, err := p.EnsureTopics(ctx, 1, 1); err != nil || created != nil {
		t.Fatalf("no topics: %v %v", created, err)
	}
	// Request-level failure (cluster gone).
	cluster.Close()
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := p.EnsureTopics(cctx, 1, 1, "im.late"); err == nil {
		t.Fatal("closed cluster accepted")
	}
}

func TestMSKIAMMechanism(t *testing.T) {
	ctx := testCtx(t)
	static := credentials.NewStaticCredentialsProvider("AKIAEXAMPLE", "secret", "session-token")
	m, err := NewSASLMechanism(ctx, "aws-msk-iam", "", "", static)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name() != "AWS_MSK_IAM" {
		t.Fatalf("name %q", m.Name())
	}
	_, first, err := m.Authenticate(ctx, "b-1.ironmesh.abc123.c2.kafka.eu-west-1.amazonaws.com:9098")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	var msg map[string]string
	if err := json.Unmarshal(first, &msg); err != nil {
		t.Fatalf("challenge %s: %v", first, err)
	}
	if !strings.HasPrefix(msg["x-amz-credential"], "AKIAEXAMPLE/") || !strings.Contains(msg["x-amz-credential"], "eu-west-1") || msg["x-amz-security-token"] != "session-token" || msg["user-agent"] != "ironmesh-bridge" {
		t.Fatalf("challenge %v", msg)
	}
	// Credential failures surface at connection time.
	failing, _ := NewSASLMechanism(ctx, "aws-msk-iam", "", "", aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, errors.New("no IMDS")
	}))
	if _, _, err := failing.Authenticate(ctx, "b-1.kafka.eu-west-1.amazonaws.com:9098"); err == nil {
		t.Fatal("credential error ignored")
	}

	// Default chain.
	orig := LoadAWSConfig
	t.Cleanup(func() { LoadAWSConfig = orig })
	LoadAWSConfig = func(context.Context) (aws.Config, error) { return aws.Config{Credentials: static}, nil }
	if m, err := NewSASLMechanism(ctx, SASLAWSMSKIAM, "", "", nil); err != nil || m == nil {
		t.Fatalf("default chain: %v", err)
	}
	LoadAWSConfig = func(context.Context) (aws.Config, error) { return aws.Config{}, nil }
	if _, err := NewSASLMechanism(ctx, SASLAWSMSKIAM, "", "", nil); err == nil {
		t.Fatal("missing credentials accepted")
	}
	LoadAWSConfig = func(context.Context) (aws.Config, error) { return aws.Config{}, errors.New("broken") }
	if _, err := NewSASLMechanism(ctx, SASLAWSMSKIAM, "", "", nil); err == nil {
		t.Fatal("config error ignored")
	}
	LoadAWSConfig = orig
	if _, err := LoadAWSConfig(ctx); err != nil {
		t.Logf("default AWS config unavailable here: %v", err)
	}
}

func TestNewSASLMechanismValidation(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"", "none", " NONE "} {
		if m, err := NewSASLMechanism(ctx, name, "", "", nil); err != nil || m != nil {
			t.Errorf("%q: %v %v", name, m, err)
		}
	}
	for _, c := range [][3]string{{"plain", "", "p"}, {"plain", "u", ""}, {"scram-sha-512", "u", ""}, {"gssapi", "u", "p"}} {
		if _, err := NewSASLMechanism(ctx, c[0], c[1], c[2], nil); err == nil {
			t.Errorf("%v accepted", c)
		}
	}
}
