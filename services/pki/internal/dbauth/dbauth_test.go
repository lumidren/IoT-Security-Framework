package dbauth

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type call struct{ endpoint, region, user string }

func fakeBuilder(calls *[]call, err error) TokenBuilder {
	return func(_ context.Context, endpoint, region, user string, _ aws.CredentialsProvider, _ ...func(*auth.BuildAuthTokenOptions)) (string, error) {
		*calls = append(*calls, call{endpoint, region, user})
		if err != nil {
			return "", err
		}
		return "token-for-" + user + "@" + endpoint, nil
	}
}

func connConfig(t *testing.T, dsn string) *pgx.ConnConfig {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.ConnConfig.Copy()
}

func TestBeforeConnectInjectsToken(t *testing.T) {
	t.Parallel()
	var calls []call
	iam := &IAM{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""), Build: fakeBuilder(&calls, nil)}
	cc := connConfig(t, "postgres://pki_app@pki.cluster-x.eu-west-1.rds.amazonaws.com:5432/pki?sslmode=require")
	if err := iam.BeforeConnect(context.Background(), cc); err != nil {
		t.Fatalf("BeforeConnect: %v", err)
	}
	if cc.Password != "token-for-pki_app@pki.cluster-x.eu-west-1.rds.amazonaws.com:5432" {
		t.Fatalf("password %q", cc.Password)
	}
	if len(calls) != 1 || calls[0] != (call{"pki.cluster-x.eu-west-1.rds.amazonaws.com:5432", "eu-west-1", "pki_app"}) {
		t.Fatalf("calls %+v", calls)
	}
	// A fresh token per connection attempt.
	if err := iam.BeforeConnect(context.Background(), connConfig(t, "postgres://pki_app@db:6432/pki?sslmode=verify-full")); err != nil || len(calls) != 2 || calls[1].endpoint != "db:6432" {
		t.Fatalf("second connect: %v %+v", err, calls)
	}
}

func TestBeforeConnectRefusesPlaintext(t *testing.T) {
	t.Parallel()
	var calls []call
	iam := &IAM{Region: "eu-west-1", Build: fakeBuilder(&calls, nil)}
	cc := connConfig(t, "postgres://pki_app@db:5432/pki?sslmode=disable")
	if err := iam.BeforeConnect(context.Background(), cc); !errors.Is(err, ErrPlaintext) {
		t.Fatalf("err %v", err)
	}
	if len(calls) != 0 || cc.Password != "" {
		t.Fatal("token minted for a plaintext connection")
	}
	// sslmode=prefer has a TLS primary and a plaintext fallback: the fallback is dropped.
	cc = connConfig(t, "postgres://pki_app@db:5432/pki?sslmode=prefer")
	if len(cc.Fallbacks) == 0 {
		t.Fatal("expected a plaintext fallback for sslmode=prefer")
	}
	cc.Fallbacks = append(cc.Fallbacks, nil, &pgconn.FallbackConfig{Host: "db", Port: 5432, TLSConfig: cc.TLSConfig})
	if err := iam.BeforeConnect(context.Background(), cc); err != nil {
		t.Fatal(err)
	}
	for _, fb := range cc.Fallbacks {
		if fb == nil || fb.TLSConfig == nil {
			t.Fatal("plaintext fallback kept")
		}
	}
	if len(cc.Fallbacks) != 1 {
		t.Fatalf("fallbacks %d", len(cc.Fallbacks))
	}
}

func TestTokenErrors(t *testing.T) {
	t.Parallel()
	var calls []call
	iam := &IAM{Region: "eu-west-1", Build: fakeBuilder(&calls, errors.New("no credentials"))}
	if _, err := iam.Token(context.Background(), "db", 5432, "pki_app"); err == nil {
		t.Fatal("builder error ignored")
	}
	if err := iam.BeforeConnect(context.Background(), connConfig(t, "postgres://pki_app@db:5432/pki?sslmode=require")); err == nil {
		t.Fatal("builder error ignored by hook")
	}
	for _, c := range []struct {
		host string
		port uint16
		user string
	}{{"", 5432, "u"}, {"db", 0, "u"}, {"db", 5432, ""}} {
		if _, err := iam.Token(context.Background(), c.host, c.port, c.user); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	// The real SDK builder is the default and signs locally (no network).
	real := &IAM{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")}
	tok, err := real.Token(context.Background(), "db.example", 5432, "pki_app")
	if err != nil || len(tok) < 40 {
		t.Fatalf("real token %q %v", tok, err)
	}
}

func TestNewIAM(t *testing.T) {
	orig := LoadConfig
	t.Cleanup(func() { LoadConfig = orig })
	creds := credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")
	var gotRegion string
	LoadConfig = func(_ context.Context, region string) (aws.Config, error) {
		gotRegion = region
		r := region
		if r == "" {
			r = "us-east-1"
		}
		return aws.Config{Region: r, Credentials: creds}, nil
	}
	iam, err := NewIAM(context.Background(), "eu-central-1")
	if err != nil || iam.Region != "eu-central-1" || gotRegion != "eu-central-1" || iam.Credentials == nil {
		t.Fatalf("NewIAM: %+v %v", iam, err)
	}
	if iam, err := NewIAM(context.Background(), ""); err != nil || iam.Region != "us-east-1" {
		t.Fatalf("default region: %+v %v", iam, err)
	}
	LoadConfig = func(context.Context, string) (aws.Config, error) { return aws.Config{}, nil }
	if _, err := NewIAM(context.Background(), ""); err == nil {
		t.Fatal("missing region accepted")
	}
	LoadConfig = func(context.Context, string) (aws.Config, error) { return aws.Config{Region: "x"}, nil }
	if _, err := NewIAM(context.Background(), ""); err == nil {
		t.Fatal("missing credentials accepted")
	}
	LoadConfig = func(context.Context, string) (aws.Config, error) { return aws.Config{}, errors.New("broken") }
	if _, err := NewIAM(context.Background(), ""); err == nil {
		t.Fatal("config error ignored")
	}
	// The default loader honours an explicit region without network access.
	LoadConfig = orig
	if cfg, err := LoadConfig(context.Background(), "ap-south-1"); err != nil || cfg.Region != "ap-south-1" {
		t.Fatalf("default loader: %v", err)
	}
}
