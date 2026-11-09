package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/bundlekey"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/config"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/dbauth"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/metrics"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store/postgres"
)

// The tests below swap package-level seams and therefore do not run in parallel.

type storeCall struct {
	url     string
	migrate bool
	hook    bool
}

func withSeams(t *testing.T) (*[]storeCall, *[]storeCall) {
	t.Helper()
	origOpen, origMigrate, origIAM, origSecrets := openPostgres, migratePostgres, newIAM, newSecretsClient
	t.Cleanup(func() {
		openPostgres, migratePostgres, newIAM, newSecretsClient = origOpen, origMigrate, origIAM, origSecrets
	})
	var opened, migrated []storeCall
	openPostgres = func(_ context.Context, url string, opts postgres.Options) (store.Store, error) {
		opened = append(opened, storeCall{url, opts.Migrate, opts.BeforeConnect != nil})
		return store.NewMemory(), nil
	}
	migratePostgres = func(_ context.Context, url string, opts postgres.Options) error {
		migrated = append(migrated, storeCall{url, true, opts.BeforeConnect != nil})
		return nil
	}
	newIAM = func(_ context.Context, region string) (*dbauth.IAM, error) {
		return &dbauth.IAM{Region: region, Build: func(context.Context, string, string, string, aws.CredentialsProvider, ...func(*auth.BuildAuthTokenOptions)) (string, error) {
			return "tok", nil
		}}, nil
	}
	return &opened, &migrated
}

func testApp(cfg *config.Config) *App {
	return &App{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestOpenStoreVariants(t *testing.T) {
	opened, migrated := withSeams(t)
	ctx := context.Background()

	// No DSN: in-memory store, no Postgres calls.
	st, err := testApp(&config.Config{}).openStore(ctx)
	if _, ok := st.(*store.Memory); err != nil || !ok || len(*opened) != 0 {
		t.Fatalf("memory store: %T %v", st, err)
	}

	// Legacy: a single (owner) DSN migrates itself.
	if _, err := testApp(&config.Config{DatabaseURL: "postgres://pki_owner:pw@db/pki"}).openStore(ctx); err != nil {
		t.Fatal(err)
	}
	if got := (*opened)[0]; got != (storeCall{"postgres://pki_owner:pw@db/pki", true, false}) || len(*migrated) != 0 {
		t.Fatalf("legacy open %+v migrated %+v", got, *migrated)
	}

	// Split DSNs: owner migrates, runtime role does not.
	cfg := &config.Config{DatabaseURL: "postgres://pki_app:pw@db/pki", MigrationDatabaseURL: "postgres://pki_owner:pw@db/pki"}
	if _, err := testApp(cfg).openStore(ctx); err != nil {
		t.Fatal(err)
	}
	if (*migrated)[0] != (storeCall{"postgres://pki_owner:pw@db/pki", true, false}) || (*opened)[1] != (storeCall{"postgres://pki_app:pw@db/pki", false, false}) {
		t.Fatalf("split: migrated %+v opened %+v", *migrated, *opened)
	}

	// IAM: runtime DSN always gets the hook; the migration DSN only without a password.
	cfg = &config.Config{DatabaseURL: "postgres://pki_app@db/pki", MigrationDatabaseURL: "postgres://pki_owner@db/pki", DBIAMAuth: true, DBIAMRegion: "eu-west-1"}
	if _, err := testApp(cfg).openStore(ctx); err != nil {
		t.Fatal(err)
	}
	if !(*migrated)[1].hook || !(*opened)[2].hook || (*opened)[2].migrate {
		t.Fatalf("iam: migrated %+v opened %+v", *migrated, *opened)
	}
	cfg.MigrationDatabaseURL = "postgres://pki_owner:secret@db/pki"
	if _, err := testApp(cfg).openStore(ctx); err != nil {
		t.Fatal(err)
	}
	if (*migrated)[2].hook {
		t.Fatal("IAM hook installed on a migration DSN with a password")
	}
}

func TestOpenStoreErrors(t *testing.T) {
	withSeams(t)
	ctx := context.Background()
	newIAM = func(context.Context, string) (*dbauth.IAM, error) { return nil, errors.New("no region") }
	if _, err := testApp(&config.Config{DatabaseURL: "postgres://db/pki", DBIAMAuth: true}).openStore(ctx); err == nil {
		t.Fatal("IAM error ignored")
	}
	migratePostgres = func(context.Context, string, postgres.Options) error { return errors.New("permission denied") }
	if _, err := testApp(&config.Config{DatabaseURL: "postgres://db/pki", MigrationDatabaseURL: "postgres://o@db/pki"}).openStore(ctx); err == nil {
		t.Fatal("migration error ignored")
	}
	openPostgres = func(context.Context, string, postgres.Options) (store.Store, error) {
		return nil, errors.New("refused")
	}
	if _, err := testApp(&config.Config{DatabaseURL: "postgres://db/pki"}).openStore(ctx); err == nil {
		t.Fatal("open error ignored")
	}
	if dsnHasPassword("::bad") {
		t.Fatal("unparsable DSN reported a password")
	}
}

type fakeSecrets struct {
	out *secretsmanager.GetSecretValueOutput
	err error
}

func (f fakeSecrets) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return f.out, f.err
}

func TestLoadBundleKeyFromSecretsManager(t *testing.T) {
	withSeams(t)
	ctx := context.Background()
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	secret := base64.StdEncoding.EncodeToString(seed)
	newSecretsClient = func(context.Context) (bundlekey.SecretsClient, error) {
		return fakeSecrets{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(secret)}}, nil
	}
	a := testApp(&config.Config{BundleKeySecretARN: "arn:aws:secretsmanager:eu-west-1:1:secret:b"})
	key, err := a.loadBundleKey(ctx)
	if err != nil || !key.Equal(ed25519.NewKeyFromSeed(seed)) {
		t.Fatalf("loadBundleKey: %v", err)
	}
	newSecretsClient = func(context.Context) (bundlekey.SecretsClient, error) {
		return fakeSecrets{err: errors.New("AccessDenied")}, nil
	}
	if _, err := a.loadBundleKey(ctx); err == nil {
		t.Fatal("GetSecretValue error ignored")
	}
	newSecretsClient = func(context.Context) (bundlekey.SecretsClient, error) { return nil, errors.New("no creds") }
	if _, err := a.loadBundleKey(ctx); err == nil {
		t.Fatal("client error ignored")
	}
}

func TestKMSProviderUnknownAndNoncePurge(t *testing.T) {
	t.Parallel()
	if _, err := testApp(&config.Config{KMS: "vault"}).kmsProvider(context.Background()); err == nil {
		t.Fatal("unknown KMS backend accepted")
	}
	a := testApp(&config.Config{})
	a.Metrics = metrics.New()
	st := store.NewMemory()
	a.Store = st
	past := time.Now().Add(-time.Hour)
	if err := st.PutNonce(context.Background(), &store.Nonce{Value: "n1", DeviceID: "dev-1", TenantID: "t", IssuedAt: past, ExpiresAt: past.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	a.maintainOnce(context.Background())
	if _, err := st.ConsumeNonce(context.Background(), "n1", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired nonce not purged: %v", err)
	}
}
