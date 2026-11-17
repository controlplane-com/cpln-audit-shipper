// Package config reads and validates the shipper's environment.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/awsauth"
)

const (
	SinkS3     = "s3"
	SinkSyslog = "syslog"
	SinkOTLP   = "otlp"

	StateS3        = "s3"
	StateVolumeSet = "volumeSet"
)

// Source configures one kind of source; each name in Names (an audit context or a cluster) is its own pipeline.
type Source struct {
	Enabled         bool
	Names           []string
	StartTime       time.Time
	EndTime         time.Time
	InitialLookback time.Duration
	SettleDelay     time.Duration
	Overlap         time.Duration
	PageSize        int
}

type Bucket struct {
	Name     string
	Region   string
	Prefix   string
	KMSKeyID string
}

type Config struct {
	Org      string
	GVC      string
	Location string
	Hostname string
	// CplnToken and CplnEndpoint are the workload's own API access, used to read its GVC.
	CplnToken    string
	CplnEndpoint string
	// Key is the service account key the audit and logs APIs accept.
	Key string

	Stream   string
	Interval time.Duration

	CplnAudit     Source
	AuditEndpoint string
	MaxRPS        float64

	K8sAudit     Source
	K8sPipeline  string
	LogsEndpoint string
	DiscoveryURL string

	Sink            string
	S3              Bucket
	Gzip            bool
	MaxObjectEvents int
	MaxObjectBytes  int

	SyslogHost            string
	SyslogPort            int
	SyslogTLS             bool
	SyslogCAFile          string
	SyslogFraming         string
	SyslogFacility        int
	SyslogSeverity        int
	SyslogMaxMessageBytes int
	SyslogTimeout         time.Duration

	OTLPEndpoint string
	OTLPHeaders  map[string]string
	OTLPCAFile   string
	OTLPGzip     bool
	OTLPTimeout  time.Duration

	State    string
	StateS3  Bucket
	StateDir string

	// NeedAWS is set when the sink or the state store is S3.
	NeedAWS bool
	AWS     awsauth.Settings

	LeaseTTL        time.Duration
	CycleBudget     time.Duration
	DrainTimeout    time.Duration
	MaxBatchEvents  int
	MaxBatchBytes   int
	HeartbeatDir    string
	HeartbeatMaxAge time.Duration

	LogLevel slog.Level
}

var (
	nameRE       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	contextRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	bucketRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionRE     = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)
	prefixRE     = regexp.MustCompile(`^[A-Za-z0-9!_.*'()=/-]*$`)
	roleARNRE    = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$`)
	externalIDRE = regexp.MustCompile(`^[\w+=,.@:/-]+$`)
	sessionRE    = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
	hostRE       = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	headerRE     = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

type parser struct {
	get  func(string) string
	errs []error
}

func (p *parser) fail(format string, args ...any) {
	p.errs = append(p.errs, fmt.Errorf(format, args...))
}

func (p *parser) str(key, def string) string {
	if v := strings.TrimSpace(p.get(key)); v != "" {
		return v
	}
	return def
}

func (p *parser) secret(key string) string { return strings.TrimSpace(p.get(key)) }

func (p *parser) duration(key, def string) time.Duration {
	raw := p.str(key, def)
	d, err := ParseDuration(raw)
	if err != nil || d < 0 {
		p.fail("%s: %q is not a duration like 90s, 15m, 24h or 7d", key, raw)
	}
	return d
}

func (p *parser) integer(key string, def, lo, hi int) int {
	raw := p.str(key, strconv.Itoa(def))
	n, err := strconv.Atoi(raw)
	if err != nil || n < lo || n > hi {
		p.fail("%s: %q must be a whole number from %d to %d", key, raw, lo, hi)
	}
	return n
}

func (p *parser) boolean(key string, def bool) bool {
	raw := p.str(key, strconv.FormatBool(def))
	b, err := strconv.ParseBool(raw)
	if err != nil {
		p.fail("%s: %q must be true or false", key, raw)
	}
	return b
}

func (p *parser) timestamp(key string) time.Time {
	raw := p.str(key, "")
	if raw == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		p.fail("%s: %q must be an RFC 3339 time such as 2026-01-01T00:00:00Z", key, raw)
	}
	return t.UTC()
}

func validURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func (p *parser) url(key, def string) string {
	raw := p.str(key, def)
	if !validURL(raw) {
		p.fail("%s: %q must be an http(s) URL", key, raw)
	}
	return raw
}

// list splits a comma-separated value and rejects names that do not match re or repeat.
func (p *parser) list(key, def string, re *regexp.Regexp, what string) []string {
	raw := p.str(key, def)
	if raw == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		switch {
		case !re.MatchString(name):
			p.fail("%s: %q is not %s", key, name, what)
		case seen[name]:
			p.fail("%s: %q is listed twice", key, name)
		default:
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// ParseDuration accepts Go durations plus a whole-day suffix (7d).
func ParseDuration(s string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

type sourceDefaults struct {
	enabled                   bool
	names, what               string
	re                        *regexp.Regexp
	lookback, settle, overlap string
	page, maxPage             int
	namesKey                  string
}

func (p *parser) source(prefix string, d sourceDefaults) Source {
	s := Source{Enabled: p.boolean(prefix+"ENABLED", d.enabled)}
	if !s.Enabled {
		return s
	}
	s.Names = p.list(prefix+d.namesKey, d.names, d.re, d.what)
	s.StartTime = p.timestamp(prefix + "START_TIME")
	s.EndTime = p.timestamp(prefix + "END_TIME")
	s.InitialLookback = p.duration(prefix+"INITIAL_LOOKBACK", d.lookback)
	s.SettleDelay = p.duration(prefix+"SETTLE_DELAY", d.settle)
	s.Overlap = p.duration(prefix+"OVERLAP", d.overlap)
	s.PageSize = p.integer(prefix+"PAGE_SIZE", d.page, 10, d.maxPage)
	if len(s.Names) == 0 {
		p.fail("%s%s must name at least one", prefix, d.namesKey)
	}
	if !s.StartTime.IsZero() && !s.EndTime.IsZero() && !s.EndTime.After(s.StartTime) {
		p.fail("%sEND_TIME must be after %sSTART_TIME", prefix, prefix)
	}
	if s.InitialLookback <= 0 {
		p.fail("%sINITIAL_LOOKBACK must be positive", prefix)
	}
	return s
}

func (p *parser) bucket(prefix string) Bucket {
	return Bucket{
		Name:     p.str(prefix+"BUCKET", ""),
		Region:   p.str(prefix+"REGION", ""),
		Prefix:   strings.Trim(p.str(prefix+"PREFIX", "cpln-audit"), "/"),
		KMSKeyID: p.str(prefix+"KMS_KEY_ID", ""),
	}
}

func (p *parser) checkBucket(prefix string, b Bucket) {
	if !bucketRE.MatchString(b.Name) || strings.Contains(b.Name, "..") {
		p.fail("%sBUCKET: %q is not a valid bucket name", prefix, b.Name)
	}
	if !regionRE.MatchString(b.Region) {
		p.fail("%sREGION: %q is not an AWS region such as us-east-1", prefix, b.Region)
	}
	if !prefixRE.MatchString(b.Prefix) || strings.Contains(b.Prefix, "//") || strings.Contains("/"+b.Prefix+"/", "/../") {
		p.fail("%sPREFIX: %q may hold only letters, digits, / and !_.*'()=- and no empty or .. segments", prefix, b.Prefix)
	}
	if strings.ContainsAny(b.KMSKeyID, " \t\n") {
		p.fail("%sKMS_KEY_ID: %q must be a KMS key ID, ARN or alias", prefix, b.KMSKeyID)
	}
}

// FromEnv reads the configuration and reports every problem at once.
func FromEnv(get func(string) string) (*Config, error) {
	p := &parser{get: get}
	c := &Config{
		Org:          p.str("CPLN_ORG", ""),
		GVC:          p.str("CPLN_GVC", ""),
		Location:     p.str("CPLN_LOCATION", "unknown"),
		Hostname:     p.str("HOSTNAME", "local"),
		CplnToken:    p.secret("CPLN_TOKEN"),
		CplnEndpoint: p.str("CPLN_ENDPOINT", ""),
		Key:          p.secret("SERVICE_ACCOUNT_KEY"),
		Stream:       p.str("STREAM", "default"),
		Interval:     p.duration("INTERVAL", "5m"),

		CplnAudit: p.source("AUDIT_", sourceDefaults{
			enabled: true, namesKey: "CONTEXTS", names: "cpln", re: contextRE, what: "an audit context name",
			lookback: "24h", settle: "1m", overlap: "15m", page: 1000, maxPage: 1000,
		}),
		K8sAudit: p.source("K8S_AUDIT_", sourceDefaults{
			enabled: false, namesKey: "CLUSTERS", re: nameRE, what: "an mk8s cluster name",
			lookback: "1h", settle: "2m", overlap: "2m", page: 5000, maxPage: 5000,
		}),
		AuditEndpoint: p.url("AUDIT_ENDPOINT", "https://audit.cpln.io"),
		K8sPipeline:   p.str("K8S_AUDIT_PIPELINE", ""),
		LogsEndpoint:  p.str("LOGS_ENDPOINT", ""),
		DiscoveryURL:  p.url("DISCOVERY_URL", "https://api.cpln.io/discovery"),

		Sink:  p.str("SINK_TYPE", ""),
		State: p.str("STATE_BACKEND", StateS3),

		LeaseTTL:        p.duration("LEASE_TTL", "5m"),
		CycleBudget:     p.duration("CYCLE_BUDGET", "30m"),
		DrainTimeout:    p.duration("DRAIN_TIMEOUT", "60s"),
		MaxBatchEvents:  p.integer("MAX_BATCH_EVENTS", 10000, 1, 1000000),
		MaxBatchBytes:   p.integer("MAX_BATCH_BYTES", 32<<20, 1<<20, 1<<30),
		HeartbeatDir:    p.str("HEARTBEAT_DIR", "/tmp/heartbeat"),
		HeartbeatMaxAge: p.duration("HEARTBEAT_MAX_AGE", "30m"),
	}

	rps := p.str("AUDIT_MAX_RPS", "10")
	if v, err := strconv.ParseFloat(rps, 64); err != nil || v <= 0 {
		p.fail("AUDIT_MAX_RPS: %q must be a positive number", rps)
	} else {
		c.MaxRPS = v
	}
	if err := c.LogLevel.UnmarshalText([]byte(p.str("LOG_LEVEL", "info"))); err != nil {
		p.fail("LOG_LEVEL: must be debug, info, warn or error")
	}
	if c.Org == "" {
		p.fail("CPLN_ORG is not set; Control Plane sets it in every workload")
	}
	if !nameRE.MatchString(c.Stream) {
		p.fail("STREAM: %q must be lowercase letters, digits and dashes, up to 63 characters", c.Stream)
	}
	if c.Interval < 10*time.Second || c.Interval > 24*time.Hour {
		p.fail("INTERVAL: %s must be between 10s and 24h", c.Interval)
	}
	if !c.CplnAudit.Enabled && !c.K8sAudit.Enabled {
		p.fail("enable at least one source: AUDIT_ENABLED or K8S_AUDIT_ENABLED")
	}
	if c.K8sAudit.Enabled {
		if c.K8sPipeline != "" && !strings.HasPrefix(c.K8sPipeline, "|") {
			p.fail("K8S_AUDIT_PIPELINE: %q must start with | (it is appended to the stream selector)", c.K8sPipeline)
		}
		if c.LogsEndpoint != "" && !validURL(c.LogsEndpoint) {
			p.fail("LOGS_ENDPOINT: %q must be an http(s) URL", c.LogsEndpoint)
		}
	}
	if c.Key == "" {
		p.fail("SERVICE_ACCOUNT_KEY is not set: it must hold a key of a service account that may read the audit contexts or logs (the audit and logs APIs do not accept the workload's CPLN_TOKEN)")
	}
	if c.LeaseTTL < time.Minute {
		p.fail("LEASE_TTL must be at least 1m")
	}
	if c.CycleBudget <= 0 {
		p.fail("CYCLE_BUDGET must be positive")
	}

	switch c.Sink {
	case SinkS3:
		c.S3 = p.bucket("S3_")
		c.Gzip = p.boolean("S3_GZIP", true)
		c.MaxObjectEvents = p.integer("MAX_OBJECT_EVENTS", 10000, 1, 1000000)
		c.MaxObjectBytes = p.integer("MAX_OBJECT_BYTES", 32<<20, 1<<20, 1<<30)
		p.checkBucket("S3_", c.S3)
		c.NeedAWS = true
	case SinkSyslog:
		c.SyslogHost = p.str("SYSLOG_HOST", "")
		c.SyslogPort = p.integer("SYSLOG_PORT", 6514, 1, 65535)
		c.SyslogTLS = p.boolean("SYSLOG_TLS", true)
		c.SyslogCAFile = p.str("SYSLOG_TLS_CA_FILE", "")
		c.SyslogFraming = p.str("SYSLOG_FRAMING", "newline")
		c.SyslogFacility = p.integer("SYSLOG_FACILITY", 1, 0, 23)
		c.SyslogSeverity = p.integer("SYSLOG_SEVERITY", 7, 0, 7)
		c.SyslogMaxMessageBytes = p.integer("SYSLOG_MAX_MESSAGE_BYTES", 32<<10, 480, 1<<20)
		c.SyslogTimeout = p.duration("SYSLOG_TIMEOUT", "60s")
		if !hostRE.MatchString(c.SyslogHost) {
			p.fail("SYSLOG_HOST: %q must be a host name or IP address", c.SyslogHost)
		}
		if c.SyslogFraming != "newline" && c.SyslogFraming != "octet-counting" {
			p.fail("SYSLOG_FRAMING: %q must be newline or octet-counting", c.SyslogFraming)
		}
		if c.SyslogCAFile != "" && !c.SyslogTLS {
			p.fail("SYSLOG_TLS_CA_FILE is set but SYSLOG_TLS is false")
		}
	case SinkOTLP:
		c.OTLPEndpoint = p.str("OTLP_ENDPOINT", "")
		c.OTLPCAFile = p.str("OTLP_TLS_CA_FILE", "")
		c.OTLPGzip = p.boolean("OTLP_GZIP", true)
		c.OTLPTimeout = p.duration("OTLP_TIMEOUT", "30s")
		if !validURL(c.OTLPEndpoint) {
			p.fail("OTLP_ENDPOINT: %q must be an http(s) URL", c.OTLPEndpoint)
		}
		c.OTLPHeaders = map[string]string{}
		if raw := p.str("OTLP_HEADERS", ""); raw != "" {
			for _, kv := range strings.Split(raw, ",") {
				k, v, ok := strings.Cut(kv, "=")
				k = strings.TrimSpace(k)
				if !ok || !headerRE.MatchString(k) {
					p.fail("OTLP_HEADERS: %q must be name=value pairs separated by commas", kv)
					continue
				}
				c.OTLPHeaders[k] = strings.TrimSpace(v)
			}
		}
		if name := p.str("OTLP_AUTH_HEADER", ""); name != "" {
			value := p.secret("OTLP_AUTH_VALUE")
			if !headerRE.MatchString(name) || value == "" {
				p.fail("OTLP_AUTH_HEADER needs a valid header name, and OTLP_AUTH_VALUE its value from the secret")
			}
			c.OTLPHeaders[name] = value
		}
	default:
		p.fail("SINK_TYPE: %q must be s3, syslog or otlp", c.Sink)
	}

	switch c.State {
	case StateS3:
		c.StateS3 = p.bucket("STATE_S3_")
		if c.StateS3.Name == "" && c.Sink == SinkS3 {
			c.StateS3 = c.S3
		} else {
			p.checkBucket("STATE_S3_", c.StateS3)
		}
		c.NeedAWS = true
	case StateVolumeSet:
		c.StateDir = p.str("STATE_DIR", "/state")
		if !strings.HasPrefix(c.StateDir, "/") {
			p.fail("STATE_DIR: %q must be an absolute path", c.StateDir)
		}
	default:
		p.fail("STATE_BACKEND: %q must be s3 or volumeSet", c.State)
	}

	if c.NeedAWS {
		region := c.StateS3.Region
		if c.Sink == SinkS3 {
			region = c.S3.Region
		}
		c.AWS = awsauth.Settings{
			Mode:            awsauth.Mode(p.str("AWS_AUTH_MODE", "")),
			Region:          region,
			AccessKeyID:     p.secret("AWS_SOURCE_ACCESS_KEY_ID"),
			SecretAccessKey: p.secret("AWS_SOURCE_SECRET_ACCESS_KEY"),
			SessionToken:    p.secret("AWS_SOURCE_SESSION_TOKEN"),
			RoleARN:         p.str("AWS_ASSUME_ROLE_ARN", ""),
			ExternalID:      p.str("AWS_ASSUME_ROLE_EXTERNAL_ID", ""),
			SessionName:     p.str("AWS_ASSUME_ROLE_SESSION_NAME", "cpln-audit-shipper"),
			Duration:        p.duration("AWS_ASSUME_ROLE_DURATION", "1h"),
		}
		validateAWS(p, c.AWS)
	}

	if len(p.errs) > 0 {
		return nil, errors.Join(p.errs...)
	}
	return c, nil
}

func validateAWS(p *parser, s awsauth.Settings) {
	hasKeys := s.AccessKeyID != "" || s.SecretAccessKey != "" || s.SessionToken != ""
	switch s.Mode {
	case awsauth.ModeIdentity:
		if hasKeys || s.RoleARN != "" || s.ExternalID != "" {
			p.fail("AWS_AUTH_MODE=identity takes its credentials from the workload identity; AWS_SOURCE_* and AWS_ASSUME_ROLE_* are only used with AWS_AUTH_MODE=secret")
		}
		return
	case awsauth.ModeSecret:
	default:
		p.fail("AWS_AUTH_MODE: %q must be identity or secret", s.Mode)
		return
	}
	if s.AccessKeyID == "" || s.SecretAccessKey == "" {
		p.fail("AWS_AUTH_MODE=secret needs both an access key ID and a secret access key from the secret")
	}
	if s.RoleARN == "" {
		if s.ExternalID != "" {
			p.fail("AWS_ASSUME_ROLE_EXTERNAL_ID is set without AWS_ASSUME_ROLE_ARN")
		}
		return
	}
	if !roleARNRE.MatchString(s.RoleARN) {
		p.fail("AWS_ASSUME_ROLE_ARN: %q is not an IAM role ARN (arn:aws:iam::<account>:role/<name>)", s.RoleARN)
	}
	if s.ExternalID != "" && (len(s.ExternalID) < 2 || len(s.ExternalID) > 1224 || !externalIDRE.MatchString(s.ExternalID)) {
		p.fail("AWS_ASSUME_ROLE_EXTERNAL_ID: must be 2 to 1224 characters of letters, digits and +=,.@:/-")
	}
	if !sessionRE.MatchString(s.SessionName) {
		p.fail("AWS_ASSUME_ROLE_SESSION_NAME: %q must be 2 to 64 characters of letters, digits and +=,.@-", s.SessionName)
	}
	if s.Duration < 15*time.Minute || s.Duration > 12*time.Hour {
		p.fail("AWS_ASSUME_ROLE_DURATION: %s must be between 15m and 12h (and within the role's maximum session duration)", s.Duration)
	}
}
