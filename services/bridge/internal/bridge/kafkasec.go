package bridge

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/sasl"
	saslaws "github.com/twmb/franz-go/pkg/sasl/aws"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// SASL mechanisms accepted by BRIDGE_KAFKA_SASL_MECHANISM.
const (
	SASLNone        = "none"
	SASLPlain       = "plain"
	SASLScramSHA512 = "scram-sha-512"
	SASLAWSMSKIAM   = "aws-msk-iam"
)

// PlatformTopics are created by BRIDGE_KAFKA_TOPICS_CREATE (API_CONTRACT.md section 6).
var PlatformTopics = []string{"im.ingest", "im.auth", "im.alerts", "im.audit", "im.commands", "im.campaigns"}

// LoadAWSConfig loads the default AWS configuration (environment, shared config, IRSA / web
// identity, ECS or EC2 instance role); a variable so tests avoid the environment.
var LoadAWSConfig = func(ctx context.Context) (aws.Config, error) { return awsconfig.LoadDefaultConfig(ctx) }

// NewSASLMechanism returns the franz-go SASL mechanism for name, or nil for "none"/"". For
// aws-msk-iam the credentials come from creds, or from the default AWS credential chain when creds
// is nil; they are resolved (and refreshed by the SDK cache) on every connection.
func NewSASLMechanism(ctx context.Context, name, username, password string, creds aws.CredentialsProvider) (sasl.Mechanism, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", SASLNone:
		return nil, nil
	case SASLPlain:
		if username == "" || password == "" {
			return nil, errors.New("kafka: SASL/PLAIN needs a username and a password")
		}
		return plain.Auth{User: username, Pass: password}.AsMechanism(), nil
	case SASLScramSHA512:
		if username == "" || password == "" {
			return nil, errors.New("kafka: SASL/SCRAM-SHA-512 needs a username and a password")
		}
		return scram.Auth{User: username, Pass: password}.AsSha512Mechanism(), nil
	case SASLAWSMSKIAM:
		if creds == nil {
			cfg, err := LoadAWSConfig(ctx)
			if err != nil {
				return nil, fmt.Errorf("kafka: load AWS configuration for MSK IAM: %w", err)
			}
			if cfg.Credentials == nil {
				return nil, errors.New("kafka: no AWS credentials provider for MSK IAM")
			}
			creds = cfg.Credentials
		}
		return saslaws.ManagedStreamingIAM(func(ctx context.Context) (saslaws.Auth, error) {
			c, err := creds.Retrieve(ctx)
			if err != nil {
				return saslaws.Auth{}, fmt.Errorf("kafka: retrieve AWS credentials: %w", err)
			}
			return saslaws.Auth{AccessKey: c.AccessKeyID, SecretKey: c.SecretAccessKey, SessionToken: c.SessionToken, UserAgent: "ironmesh-bridge"}, nil
		}), nil
	}
	return nil, fmt.Errorf("kafka: unknown SASL mechanism %q (none, plain, scram-sha-512, aws-msk-iam)", name)
}

// EnsureTopics creates topics with the given partition count and replication factor through the
// Kafka admin API. Topics that already exist count as success (their settings are not changed).
// It returns the topics that were newly created.
func (p *KafkaProducer) EnsureTopics(ctx context.Context, partitions int32, replication int16, topics ...string) ([]string, error) {
	if len(topics) == 0 {
		return nil, nil
	}
	resp, err := kadm.NewClient(p.cl).CreateTopics(ctx, partitions, replication, nil, topics...)
	if err != nil {
		return nil, fmt.Errorf("kafka: create topics: %w", err)
	}
	var created []string
	var errs []error
	for _, t := range resp.Sorted() {
		switch {
		case t.Err == nil:
			created = append(created, t.Topic)
		case errors.Is(t.Err, kerr.TopicAlreadyExists):
		default:
			msg := t.Err.Error()
			if t.ErrMessage != "" {
				msg += ": " + t.ErrMessage
			}
			errs = append(errs, fmt.Errorf("kafka: create topic %s: %s", t.Topic, msg))
		}
	}
	return created, errors.Join(errs...)
}
