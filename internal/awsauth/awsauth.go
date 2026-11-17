// Package awsauth builds AWS credentials for the two supported modes.
package awsauth

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Mode string

const (
	// ModeIdentity uses the SDK's default credential chain, which picks up the Control Plane identity's cloud access.
	ModeIdentity Mode = "identity"
	// ModeSecret uses access keys from a Control Plane secret, optionally to assume a role.
	ModeSecret Mode = "secret"
)

type Settings struct {
	Mode            Mode
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	RoleARN         string
	ExternalID      string
	SessionName     string
	Duration        time.Duration
}

// Load returns an AWS config whose credentials refresh themselves: assumed-role credentials are renewed before expiry.
func Load(ctx context.Context, s Settings) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(s.Region),
		config.WithRetryer(func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 6
				o.MaxBackoff = 20 * time.Second
			})
		}),
	}
	if s.Mode == ModeSecret {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s.AccessKeyID, s.SecretAccessKey, s.SessionToken)))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("loading AWS configuration: %w", err)
	}
	if s.Mode == ModeSecret && s.RoleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(AssumeRoleProvider(sts.NewFromConfig(cfg), s),
			func(o *aws.CredentialsCacheOptions) {
				o.ExpiryWindow = 5 * time.Minute
				o.ExpiryWindowJitterFrac = 0.2
			})
	}
	return cfg, nil
}

func AssumeRoleProvider(client stscreds.AssumeRoleAPIClient, s Settings) *stscreds.AssumeRoleProvider {
	return stscreds.NewAssumeRoleProvider(client, s.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = s.SessionName
		o.Duration = s.Duration
		if s.ExternalID != "" {
			o.ExternalID = aws.String(s.ExternalID)
		}
	})
}

// Describe names the credential source for logs, without any secret material.
func Describe(s Settings) string {
	switch {
	case s.Mode == ModeIdentity:
		return "Control Plane identity (default credential chain)"
	case s.RoleARN != "":
		return "secret access key assuming " + s.RoleARN
	default:
		return "secret access key"
	}
}
