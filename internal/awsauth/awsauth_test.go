package awsauth

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func TestSecretModeUsesTheSecretKeysDirectly(t *testing.T) {
	cfg, err := Load(context.Background(), Settings{Mode: ModeSecret, Region: "us-east-1",
		AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "AKIAEXAMPLE" || creds.SecretAccessKey != "secret" || creds.SessionToken != "token" {
		t.Fatalf("credentials = %+v", creds)
	}
}

type fakeSTS struct {
	calls []*sts.AssumeRoleInput
	ttl   time.Duration
}

func (f *fakeSTS) AssumeRole(_ context.Context, in *sts.AssumeRoleInput, _ ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.calls = append(f.calls, in)
	n := len(f.calls)
	return &sts.AssumeRoleOutput{Credentials: &ststypes.Credentials{
		AccessKeyId:     aws.String("ASIA" + string(rune('0'+n))),
		SecretAccessKey: aws.String("assumed"),
		SessionToken:    aws.String("session"),
		Expiration:      aws.Time(time.Now().Add(f.ttl)),
	}}, nil
}

func TestAssumeRolePassesRoleExternalIDAndRefreshesBeforeExpiry(t *testing.T) {
	f := &fakeSTS{ttl: 2 * time.Minute}
	s := Settings{RoleARN: "arn:aws:iam::123456789012:role/audit-writer", ExternalID: "cpln-acme",
		SessionName: "cpln-audit-trail-s3-sync", Duration: time.Hour}
	cache := aws.NewCredentialsCache(AssumeRoleProvider(f, s), func(o *aws.CredentialsCacheOptions) {
		o.ExpiryWindow = 5 * time.Minute
	})

	first, err := cache.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	in := f.calls[0]
	if aws.ToString(in.RoleArn) != s.RoleARN || aws.ToString(in.ExternalId) != "cpln-acme" ||
		aws.ToString(in.RoleSessionName) != s.SessionName || aws.ToInt32(in.DurationSeconds) != 3600 {
		t.Fatalf("AssumeRole input = %+v", in)
	}
	if !first.CanExpire {
		t.Fatal("assumed-role credentials must expire so the cache refreshes them")
	}
	second, err := cache.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || second.AccessKeyID == first.AccessKeyID {
		t.Fatalf("credentials inside the expiry window were not refreshed: %d AssumeRole calls", len(f.calls))
	}
}

func TestAssumeRoleWithoutExternalIDOmitsIt(t *testing.T) {
	f := &fakeSTS{ttl: time.Hour}
	if _, err := AssumeRoleProvider(f, Settings{RoleARN: "arn:aws:iam::123456789012:role/x", SessionName: "s1", Duration: time.Hour}).Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.calls[0].ExternalId != nil {
		t.Fatalf("external ID sent although none was configured: %q", aws.ToString(f.calls[0].ExternalId))
	}
}
