// Package postgres implements store.Store on PostgreSQL using pgx v5.
//
// Tests in this package require a database and are skipped unless
// PKI_TEST_DATABASE_URL is set (they run the shared storetest suite).
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lumidren/IoT-Security-Framework/services/pki/internal/store"
)

type commandTag = pgconn.CommandTag

// Store is a Postgres-backed store.Store.
type Store struct {
	pool *pgxpool.Pool
}

// Options tune OpenWithOptions.
type Options struct {
	// Migrate applies the embedded migrations after connecting. It must be
	// false when the DSN uses the non-owner runtime role (pki_app), which
	// cannot create or alter tables; run MigrateURL with the owner DSN first.
	Migrate bool
	// BeforeConnect runs before every new connection, e.g. to inject an RDS
	// IAM authentication token as the password.
	BeforeConnect func(context.Context, *pgx.ConnConfig) error
	// MaxConns overrides the pool size (default 16).
	MaxConns int32
}

// Open connects to url, applies migrations and returns the store.
func Open(ctx context.Context, url string) (*Store, error) {
	return OpenWithOptions(ctx, url, Options{Migrate: true})
}

// PoolConfig parses url into a pool configuration with the service defaults
// and the hooks of opts.
func PoolConfig(url string, opts Options) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse database url: %w", err)
	}
	cfg.MaxConns = 16
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	// An IAM token only has to be valid when a connection is established, so
	// the hook mints one per new connection and pool lifetimes stay as is.
	cfg.BeforeConnect = opts.BeforeConnect
	return cfg, nil
}

// OpenWithOptions connects to url and returns the store, applying the
// migrations only when opts.Migrate is set.
func OpenWithOptions(ctx context.Context, url string, opts Options) (*Store, error) {
	cfg, err := PoolConfig(url, opts)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if opts.Migrate {
		if err := s.Migrate(ctx); err != nil {
			pool.Close()
			return nil, err
		}
	}
	return s, nil
}

// MigrateURL connects with url (the schema owner, PKI_MIGRATION_DATABASE_URL),
// applies the pending migrations and disconnects.
func MigrateURL(ctx context.Context, url string, opts Options) error {
	opts.Migrate = true
	opts.MaxConns = 2
	s, err := OpenWithOptions(ctx, url, opts)
	if err != nil {
		return err
	}
	return s.Close()
}

// NewFromPool wraps an existing pool without running migrations.
func NewFromPool(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Ping implements store.Store.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: ping: %w", err)
	}
	return nil
}

// Close implements store.Store.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

const certColumns = `serial, device_id, tenant_id, kind, issuer_cn, not_before, not_after, spki_sha256, assurance, der, issued_at`

func scanCert(row pgx.Row) (*store.CertificateRecord, error) {
	var rec store.CertificateRecord
	err := row.Scan(&rec.Serial, &rec.DeviceID, &rec.TenantID, &rec.Kind, &rec.IssuerCN, &rec.NotBefore, &rec.NotAfter,
		&rec.SPKISHA256, &rec.Assurance, &rec.DER, &rec.IssuedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &rec, nil
}

// PutCertificate implements store.Store.
func (s *Store) PutCertificate(ctx context.Context, rec *store.CertificateRecord) error {
	if rec.Serial == "" {
		return errors.New("store: serial is required")
	}
	issued := rec.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO certificates (`+certColumns+`)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rec.Serial, rec.DeviceID, rec.TenantID, rec.Kind, rec.IssuerCN, rec.NotBefore, rec.NotAfter,
		rec.SPKISHA256, rec.Assurance, rec.DER, issued)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

// GetCertificate implements store.Store.
func (s *Store) GetCertificate(ctx context.Context, serial string) (*store.CertificateRecord, error) {
	return scanCert(s.pool.QueryRow(ctx, `SELECT `+certColumns+` FROM certificates WHERE serial = $1`, serial))
}

// ListCertificatesByDevice implements store.Store.
func (s *Store) ListCertificatesByDevice(ctx context.Context, deviceID string) ([]*store.CertificateRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+certColumns+` FROM certificates WHERE device_id = $1 ORDER BY issued_at DESC, serial ASC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*store.CertificateRecord{}
	for rows.Next() {
		rec, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// CountExpiring implements store.Store.
func (s *Store) CountExpiring(ctx context.Context, from, until time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM certificates c
        WHERE c.not_after > $1 AND c.not_after <= $2
          AND NOT EXISTS (SELECT 1 FROM revocations r WHERE r.serial = c.serial)`, from, until).Scan(&n)
	return n, err
}

// Stats implements store.Store.
func (s *Store) Stats(ctx context.Context, now time.Time) (*store.Stats, error) {
	var st store.Stats
	err := s.pool.QueryRow(ctx, `SELECT
        (SELECT count(*) FROM certificates),
        (SELECT count(*) FROM certificates c WHERE EXISTS (SELECT 1 FROM revocations r WHERE r.serial = c.serial)),
        (SELECT count(*) FROM certificates WHERE not_after <= $1)`, now).Scan(&st.Total, &st.Revoked, &st.Expired)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// AddRevocation implements store.Store.
func (s *Store) AddRevocation(ctx context.Context, rev *store.Revocation) error {
	if rev.Serial == "" {
		return errors.New("store: serial is required")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO revocations (serial, device_id, tenant_id, issuer_cn, not_after, reason, revoked_at, revoked_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		rev.Serial, rev.DeviceID, rev.TenantID, rev.IssuerCN, rev.NotAfter, rev.Reason, rev.RevokedAt, rev.RevokedBy)
	if isUniqueViolation(err) {
		return store.ErrAlreadyRevoked
	}
	return err
}

const revColumns = `serial, device_id, tenant_id, issuer_cn, not_after, reason, revoked_at, revoked_by`

func scanRevocation(row pgx.Row) (*store.Revocation, error) {
	var rev store.Revocation
	err := row.Scan(&rev.Serial, &rev.DeviceID, &rev.TenantID, &rev.IssuerCN, &rev.NotAfter, &rev.Reason, &rev.RevokedAt, &rev.RevokedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &rev, nil
}

// GetRevocation implements store.Store.
func (s *Store) GetRevocation(ctx context.Context, serial string) (*store.Revocation, error) {
	return scanRevocation(s.pool.QueryRow(ctx, `SELECT `+revColumns+` FROM revocations WHERE serial = $1`, serial))
}

// ListRevocations implements store.Store.
func (s *Store) ListRevocations(ctx context.Context) ([]*store.Revocation, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+revColumns+` FROM revocations ORDER BY serial`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*store.Revocation{}
	for rows.Next() {
		rev, err := scanRevocation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

// PutNonce implements store.Store.
func (s *Store) PutNonce(ctx context.Context, n *store.Nonce) error {
	if n.Value == "" {
		return errors.New("store: nonce value is required")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO nonces (value, device_id, tenant_id, issued_at, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		n.Value, n.DeviceID, n.TenantID, n.IssuedAt, n.ExpiresAt)
	if isUniqueViolation(err) {
		return store.ErrAlreadyExists
	}
	return err
}

// ConsumeNonce implements store.Store.
func (s *Store) ConsumeNonce(ctx context.Context, value string, now time.Time) (*store.Nonce, error) {
	var n store.Nonce
	err := s.pool.QueryRow(ctx, `DELETE FROM nonces WHERE value = $1 RETURNING value, device_id, tenant_id, issued_at, expires_at`, value).
		Scan(&n.Value, &n.DeviceID, &n.TenantID, &n.IssuedAt, &n.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if !n.ExpiresAt.After(now) {
		return &n, store.ErrNonceExpired
	}
	return &n, nil
}

// DeleteExpiredNonces implements store.Store.
func (s *Store) DeleteExpiredNonces(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM nonces WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// NextCRLNumber implements store.Store.
func (s *Store) NextCRLNumber(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `UPDATE crl_counter SET number = number + 1 WHERE id = 1 RETURNING number`).Scan(&n)
	return n, err
}

// GetTenantPolicy implements store.Store.
func (s *Store) GetTenantPolicy(ctx context.Context, tenantID string) (*store.TenantPolicy, error) {
	var p store.TenantPolicy
	err := s.pool.QueryRow(ctx, `SELECT tenant_id, allow_software_keys, allowed_pcr_digests, ak_ca_pem, tenant_cmd_pubkey,
        fw_signing_pubkeys, broker_host, broker_port, updated_at FROM tenant_policies WHERE tenant_id = $1`, tenantID).
		Scan(&p.TenantID, &p.AllowSoftwareKeys, &p.AllowedPCRDigests, &p.AKCAPEM, &p.TenantCmdPubKey, &p.FwSigningPubKeys,
			&p.BrokerHost, &p.BrokerPort, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// PutTenantPolicy implements store.Store.
func (s *Store) PutTenantPolicy(ctx context.Context, p *store.TenantPolicy) error {
	if p.TenantID == "" {
		return errors.New("store: tenant id is required")
	}
	digests := p.AllowedPCRDigests
	if digests == nil {
		digests = []string{}
	}
	fwKeys := p.FwSigningPubKeys
	if fwKeys == nil {
		fwKeys = [][]byte{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO tenant_policies (tenant_id, allow_software_keys, allowed_pcr_digests, ak_ca_pem,
        tenant_cmd_pubkey, fw_signing_pubkeys, broker_host, broker_port, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
        ON CONFLICT (tenant_id) DO UPDATE SET allow_software_keys = EXCLUDED.allow_software_keys,
            allowed_pcr_digests = EXCLUDED.allowed_pcr_digests, ak_ca_pem = EXCLUDED.ak_ca_pem,
            tenant_cmd_pubkey = EXCLUDED.tenant_cmd_pubkey, fw_signing_pubkeys = EXCLUDED.fw_signing_pubkeys,
            broker_host = EXCLUDED.broker_host, broker_port = EXCLUDED.broker_port, updated_at = now()`,
		p.TenantID, p.AllowSoftwareKeys, digests, p.AKCAPEM, p.TenantCmdPubKey, fwKeys, p.BrokerHost, p.BrokerPort)
	return err
}

// Truncate removes all rows; used by integration tests.
func (s *Store) Truncate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE certificates, revocations, nonces, tenant_policies; UPDATE crl_counter SET number = 0 WHERE id = 1`)
	return err
}

var _ store.Store = (*Store)(nil)
