// Package dbauth supplies database credentials that cannot live in a DSN:
// Amazon RDS / Aurora IAM authentication tokens, generated per connection in
// a pgx BeforeConnect hook (PKI_DB_IAM_AUTH=true).
//
// An IAM token is a 15-minute SigV4-presigned "connect" request for
// <host>:<port>/<user>; RDS only accepts it over TLS, so the hook refuses
// connection attempts that would send it in plaintext.
package dbauth

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jackc/pgx/v5"
)

// TokenBuilder has the signature of auth.BuildAuthToken.
type TokenBuilder func(ctx context.Context, endpoint, region, dbUser string, creds aws.CredentialsProvider, optFns ...func(*auth.BuildAuthTokenOptions)) (string, error)

// ErrPlaintext is returned when IAM authentication would run without TLS.
var ErrPlaintext = errors.New("dbauth: RDS IAM authentication requires TLS (use sslmode=require, verify-ca or verify-full)")

// IAM generates RDS IAM authentication tokens.
type IAM struct {
	Region      string
	Credentials aws.CredentialsProvider
	// Build defaults to auth.BuildAuthToken.
	Build TokenBuilder
}

// LoadConfig loads the default AWS configuration (environment, shared
// config, web identity / IRSA, ECS or EC2 role). It is a variable so tests
// can avoid touching the environment.
var LoadConfig = func(ctx context.Context, region string) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	return awsconfig.LoadDefaultConfig(ctx, opts...)
}

// NewIAM builds an IAM token source from the default AWS credential chain.
// region overrides the region of the AWS configuration (AWS_REGION).
func NewIAM(ctx context.Context, region string) (*IAM, error) {
	cfg, err := LoadConfig(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("dbauth: load AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("dbauth: no AWS region configured (set PKI_DB_IAM_REGION or AWS_REGION)")
	}
	if cfg.Credentials == nil {
		return nil, errors.New("dbauth: no AWS credentials provider configured")
	}
	return &IAM{Region: cfg.Region, Credentials: cfg.Credentials}, nil
}

// Token returns an authentication token for user at host:port.
func (i *IAM) Token(ctx context.Context, host string, port uint16, user string) (string, error) {
	if host == "" || port == 0 || user == "" {
		return "", errors.New("dbauth: host, port and user are required for an IAM token")
	}
	build := i.Build
	if build == nil {
		build = auth.BuildAuthToken
	}
	endpoint := host + ":" + strconv.Itoa(int(port))
	tok, err := build(ctx, endpoint, i.Region, user, i.Credentials)
	if err != nil {
		return "", fmt.Errorf("dbauth: build RDS IAM token for %s@%s: %w", user, endpoint, err)
	}
	return tok, nil
}

// BeforeConnect is a pgxpool.Config.BeforeConnect hook: it replaces the
// password with a fresh IAM token and drops plaintext fallbacks (sslmode=prefer
// / allow) so the token is never sent without TLS.
func (i *IAM) BeforeConnect(ctx context.Context, cc *pgx.ConnConfig) error {
	if cc.TLSConfig == nil {
		return ErrPlaintext
	}
	tls := cc.Fallbacks[:0]
	for _, fb := range cc.Fallbacks {
		if fb != nil && fb.TLSConfig != nil {
			tls = append(tls, fb)
		}
	}
	cc.Fallbacks = tls
	tok, err := i.Token(ctx, cc.Host, cc.Port, cc.User)
	if err != nil {
		return err
	}
	cc.Password = tok
	return nil
}
