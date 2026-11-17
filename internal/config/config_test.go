package config

import (
	"strings"
	"testing"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/awsauth"
)

func env(overrides map[string]string) func(string) string {
	base := map[string]string{
		"CPLN_ORG": "acme", "SERVICE_ACCOUNT_KEY": "service-account-key", "SINK_TYPE": "s3",
		"S3_BUCKET": "acme-audit", "S3_REGION": "us-east-1", "S3_PREFIX": "/audit/", "AWS_AUTH_MODE": "identity",
	}
	for k, v := range overrides {
		if v == "-" {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func TestS3SinkDefaults(t *testing.T) {
	c, err := FromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !c.CplnAudit.Enabled || len(c.CplnAudit.Names) != 1 || c.CplnAudit.Names[0] != "cpln" || c.K8sAudit.Enabled {
		t.Fatalf("sources: %+v %+v", c.CplnAudit, c.K8sAudit)
	}
	if c.Stream != "default" || c.Interval != 5*time.Minute || c.S3.Prefix != "audit" || !c.Gzip {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.CplnAudit.InitialLookback != 24*time.Hour || c.CplnAudit.Overlap != 15*time.Minute || c.CplnAudit.SettleDelay != time.Minute || c.CplnAudit.PageSize != 1000 {
		t.Fatalf("unexpected timing defaults: %+v", c.CplnAudit)
	}
	if c.State != StateS3 || c.StateS3 != c.S3 || !c.NeedAWS || c.AWS.Mode != awsauth.ModeIdentity || c.AWS.Region != "us-east-1" {
		t.Fatalf("state %s %+v aws %+v", c.State, c.StateS3, c.AWS)
	}
}

func TestSyslogWithVolumeSetStateNeedsNoAWS(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"SINK_TYPE": "syslog", "SYSLOG_HOST": "syslog.example.com", "SYSLOG_PORT": "5550",
		"STATE_BACKEND": "volumeSet", "AWS_AUTH_MODE": "-", "S3_BUCKET": "-", "S3_REGION": "-",
		"AUDIT_ENABLED": "false", "K8S_AUDIT_ENABLED": "true", "K8S_AUDIT_CLUSTERS": "prod-cluster, staging-cluster",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.NeedAWS || !c.SyslogTLS || c.SyslogFraming != "newline" || c.SyslogPort != 5550 || c.StateDir != "/state" {
		t.Fatalf("syslog config: %+v", c)
	}
	k := c.K8sAudit
	if len(k.Names) != 2 || k.SettleDelay != 2*time.Minute || k.Overlap != 2*time.Minute || k.PageSize != 5000 || k.InitialLookback != time.Hour {
		t.Fatalf("k8s source: %+v", k)
	}
}

func TestOTLPHeadersAndAuthHeaderFromTheSecret(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"SINK_TYPE": "otlp", "OTLP_ENDPOINT": "https://otlp.example.com", "OTLP_HEADERS": "X-Scope-OrgID=acme, x-tenant = t1",
		"OTLP_AUTH_HEADER": "Authorization", "OTLP_AUTH_VALUE": "Bearer TOPSECRETVALUE",
		"STATE_S3_BUCKET": "acme-state", "STATE_S3_REGION": "eu-west-1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.OTLPHeaders["X-Scope-OrgID"] != "acme" || c.OTLPHeaders["x-tenant"] != "t1" || c.OTLPHeaders["Authorization"] != "Bearer TOPSECRETVALUE" {
		t.Fatalf("headers = %v", c.OTLPHeaders)
	}
	if c.StateS3.Name != "acme-state" || c.StateS3.Prefix != "cpln-audit" || c.AWS.Region != "eu-west-1" {
		t.Fatalf("state bucket %+v region %s", c.StateS3, c.AWS.Region)
	}
}

func TestSecretModes(t *testing.T) {
	keys := map[string]string{"AWS_AUTH_MODE": "secret", "AWS_SOURCE_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SOURCE_SECRET_ACCESS_KEY": "s3cr3t"}
	c, err := FromEnv(env(keys))
	if err != nil {
		t.Fatalf("direct secret: %v", err)
	}
	if c.AWS.RoleARN != "" || c.AWS.AccessKeyID != "AKIAEXAMPLE" {
		t.Fatalf("direct secret parsed as %+v", c.AWS)
	}
	keys["AWS_SOURCE_SESSION_TOKEN"] = "tok"
	keys["AWS_ASSUME_ROLE_ARN"] = "arn:aws:iam::123456789012:role/audit-writer"
	keys["AWS_ASSUME_ROLE_EXTERNAL_ID"] = "cpln-acme"
	keys["AWS_ASSUME_ROLE_DURATION"] = "2h"
	c, err = FromEnv(env(keys))
	if err != nil {
		t.Fatalf("assume role: %v", err)
	}
	if c.AWS.Duration != 2*time.Hour || c.AWS.ExternalID != "cpln-acme" || c.AWS.SessionName != "cpln-audit-shipper" {
		t.Fatalf("assume role parsed as %+v", c.AWS)
	}
}

func TestInvalidSettingsAreRejectedTogetherWithoutLeakingSecrets(t *testing.T) {
	secret := map[string]string{"AWS_AUTH_MODE": "secret", "AWS_SOURCE_ACCESS_KEY_ID": "a", "AWS_SOURCE_SECRET_ACCESS_KEY": "TOPSECRETVALUE"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range secret {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	syslogVS := map[string]string{"SINK_TYPE": "syslog", "SYSLOG_HOST": "h.example.com", "STATE_BACKEND": "volumeSet", "AWS_AUTH_MODE": "-"}
	cases := map[string]struct {
		env  map[string]string
		want string
	}{
		"identity with keys":      {map[string]string{"AWS_SOURCE_ACCESS_KEY_ID": "AKIAEXAMPLE"}, "only used with AWS_AUTH_MODE=secret"},
		"unknown mode":            {map[string]string{"AWS_AUTH_MODE": "static"}, "must be identity or secret"},
		"secret without key":      {map[string]string{"AWS_AUTH_MODE": "secret", "AWS_SOURCE_ACCESS_KEY_ID": "AKIAEXAMPLE"}, "needs both"},
		"external id without arn": {with(map[string]string{"AWS_ASSUME_ROLE_EXTERNAL_ID": "x1"}), "without AWS_ASSUME_ROLE_ARN"},
		"user arn as role":        {with(map[string]string{"AWS_ASSUME_ROLE_ARN": "arn:aws:iam::123456789012:user/bob"}), "is not an IAM role ARN"},
		"role duration":           {with(map[string]string{"AWS_ASSUME_ROLE_ARN": "arn:aws:iam::123456789012:role/x", "AWS_ASSUME_ROLE_DURATION": "5m"}), "between 15m and 12h"},
		"missing bucket":          {map[string]string{"S3_BUCKET": ""}, "S3_BUCKET"},
		"bad region":              {map[string]string{"S3_REGION": "US East"}, "S3_REGION"},
		"bad stream":              {map[string]string{"STREAM": "Default_1"}, "STREAM"},
		"end before start":        {map[string]string{"AUDIT_START_TIME": "2026-02-01T00:00:00Z", "AUDIT_END_TIME": "2026-01-01T00:00:00Z"}, "after AUDIT_START_TIME"},
		"bad time":                {map[string]string{"AUDIT_START_TIME": "yesterday"}, "RFC 3339"},
		"bad duration":            {map[string]string{"AUDIT_OVERLAP": "fifteen"}, "AUDIT_OVERLAP"},
		"audit page size":         {map[string]string{"AUDIT_PAGE_SIZE": "5000"}, "AUDIT_PAGE_SIZE"},
		"prefix traversal":        {map[string]string{"S3_PREFIX": "a/../b"}, "S3_PREFIX"},
		"bad context":             {map[string]string{"AUDIT_CONTEXTS": "cpln,my ctx"}, "AUDIT_CONTEXTS"},
		"duplicate context":       {map[string]string{"AUDIT_CONTEXTS": "cpln, cpln"}, "listed twice"},
		"no key":                  {map[string]string{"SERVICE_ACCOUNT_KEY": ""}, "SERVICE_ACCOUNT_KEY"},
		"no source":               {map[string]string{"AUDIT_ENABLED": "false"}, "enable at least one source"},
		"k8s without clusters":    {map[string]string{"K8S_AUDIT_ENABLED": "true"}, "K8S_AUDIT_CLUSTERS"},
		"bad cluster":             {map[string]string{"K8S_AUDIT_ENABLED": "true", "K8S_AUDIT_CLUSTERS": "Prod_Cluster"}, "mk8s cluster name"},
		"pipeline without pipe":   {map[string]string{"K8S_AUDIT_ENABLED": "true", "K8S_AUDIT_CLUSTERS": "c", "K8S_AUDIT_PIPELINE": `json`}, "must start with |"},
		"unknown sink":            {map[string]string{"SINK_TYPE": "kafka"}, "SINK_TYPE"},
		"unknown state":           {map[string]string{"STATE_BACKEND": "redis"}, "STATE_BACKEND"},
		"syslog host":             {map[string]string{"SINK_TYPE": "syslog", "SYSLOG_HOST": "bad host", "STATE_BACKEND": "volumeSet"}, "SYSLOG_HOST"},
		"syslog framing":          {with(map[string]string{"SINK_TYPE": "syslog", "SYSLOG_HOST": "h", "SYSLOG_FRAMING": "lf", "STATE_BACKEND": "volumeSet"}), "SYSLOG_FRAMING"},
		"otlp endpoint":           {map[string]string{"SINK_TYPE": "otlp", "OTLP_ENDPOINT": "collector:4318", "STATE_BACKEND": "volumeSet"}, "OTLP_ENDPOINT"},
		"otlp auth without value": {map[string]string{"SINK_TYPE": "otlp", "OTLP_ENDPOINT": "https://c", "OTLP_AUTH_HEADER": "Authorization", "STATE_BACKEND": "volumeSet"}, "OTLP_AUTH_VALUE"},
		"state bucket for syslog": {map[string]string{"SINK_TYPE": "syslog", "SYSLOG_HOST": "h"}, "STATE_S3_BUCKET"},
		"interval":                {map[string]string{"INTERVAL": "1s"}, "INTERVAL"},
		"relative state dir": {func() map[string]string {
			m := map[string]string{"STATE_DIR": "state"}
			for k, v := range syslogVS {
				m[k] = v
			}
			return m
		}(), "STATE_DIR"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := FromEnv(env(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "TOPSECRETVALUE") || strings.Contains(err.Error(), "service-account-key") {
				t.Fatalf("error leaks a secret: %v", err)
			}
		})
	}
}

func TestParseDurationAcceptsDays(t *testing.T) {
	d, err := ParseDuration("7d")
	if err != nil || d != 7*24*time.Hour {
		t.Fatalf("7d = %s, %v", d, err)
	}
}

func TestSeveralAuditContexts(t *testing.T) {
	c, err := FromEnv(env(map[string]string{"AUDIT_CONTEXTS": "cpln, orders-audit"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.CplnAudit.Names) != 2 || c.CplnAudit.Names[1] != "orders-audit" {
		t.Fatalf("contexts = %q", c.CplnAudit.Names)
	}
}
