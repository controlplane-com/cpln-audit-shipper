// Command cpln-audit-shipper ships Control Plane audit trail events and mk8s Kubernetes audit logs to S3, syslog
// or an OTLP endpoint. It runs one pipeline per audit context and cluster, each on its own loop.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/controlplane-com/cpln-audit-shipper/internal/auditapi"
	"github.com/controlplane-com/cpln-audit-shipper/internal/awsauth"
	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/config"
	"github.com/controlplane-com/cpln-audit-shipper/internal/filestore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/lokiapi"
	"github.com/controlplane-com/cpln-audit-shipper/internal/objstore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/pipeline"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
	"github.com/controlplane-com/cpln-audit-shipper/internal/sakey"
	"github.com/controlplane-com/cpln-audit-shipper/internal/sink/otlpsink"
	"github.com/controlplane-com/cpln-audit-shipper/internal/sink/s3sink"
	"github.com/controlplane-com/cpln-audit-shipper/internal/sink/syslogsink"
)

var version = "dev"

const (
	exitOK     = 0
	exitFailed = 1
	exitConfig = 2
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Getenv, time.Now()))
	}
	os.Exit(run())
}

func run() int {
	cfg, cfgErr := config.FromEnv(os.Getenv)
	level := slog.LevelInfo
	if cfg != nil {
		level = cfg.LogLevel
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	if cfgErr != nil {
		log.Error("invalid configuration", "error", cfgErr.Error(), "version", version)
		return exitConfig
	}
	setMemoryLimit(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	owner := fmt.Sprintf("%s/%s/%s", cfg.Location, cfg.Hostname, randomHex(4))
	log = log.With("replica", owner, "org", cfg.Org, "stream", cfg.Stream)
	log.Info("shipper starting", "version", version, "sink", cfg.Sink, "state", cfg.State, "interval", cfg.Interval.String(),
		"cpln_audit_contexts", names(cfg.CplnAudit), "k8s_audit_clusters", names(cfg.K8sAudit))
	hb := &heartbeat{dir: cfg.HeartbeatDir}
	if err := os.MkdirAll(hb.dir, 0o750); err != nil {
		log.Error("cannot create the heartbeat directory", "dir", hb.dir, "error", err.Error())
		return exitFailed
	}

	var awsCfg aws.Config
	if cfg.NeedAWS {
		var err error
		if awsCfg, err = awsauth.Load(ctx, cfg.AWS); err != nil {
			log.Error("invalid AWS configuration", "error", err.Error())
			return exitConfig
		}
		if _, err := awsCfg.Credentials.Retrieve(ctx); err != nil {
			log.Error("cannot obtain AWS credentials", "error", err.Error(), "hint", credentialsHint(cfg))
			return exitFailed
		}
		log.Info("AWS credentials ready", "aws_auth", awsauth.Describe(cfg.AWS))
	}

	var state objstore.Store
	statePrefix := ""
	switch cfg.State {
	case config.StateS3:
		state = bucketStore(awsCfg, cfg.StateS3)
		statePrefix = cfg.StateS3.Prefix
	case config.StateVolumeSet:
		if err := checkSingleLocation(ctx, cfg, log); err != nil {
			log.Error("volume set state needs a single-location GVC", "error", err.Error(),
				"hint", "use state backend s3 for a GVC with several locations; volume sets are per location and cannot keep replicas in different locations apart")
			return exitConfig
		}
		lock, code := acquireLock(ctx, cfg, hb, log)
		if lock == nil {
			return code
		}
		defer lock.Release()
		state = &filestore.Store{Dir: cfg.StateDir}
	}

	if cfg.Key == "" {
		minter := sakey.New(sakey.Config{
			Endpoint: cfg.CplnEndpoint, Token: cfg.CplnToken, Org: cfg.Org, Name: cfg.ServiceAccountName,
			Location: cfg.Location, Host: cfg.Hostname, Logger: log,
		})
		key, err := mintKey(ctx, minter, hb, log)
		if err != nil {
			if ctx.Err() != nil {
				return exitOK
			}
			log.Error("cannot add a key to the service account", "service_account", cfg.ServiceAccountName, "error", err.Error(),
				"hint", "the workload identity needs addKey, edit and view on the service account (the template grants them), and the account holds at most 10 keys")
			return exitFailed
		}
		log.Info("added a key to the service account", "service_account", cfg.ServiceAccountName)
		cfg.Key = key.Value
		defer func() {
			// The run's context is done by now; removing the key gets a short context of its own.
			rctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := minter.Remove(rctx, key); err != nil {
				log.Warn("could not remove this replica's service account key; a later start in this location removes it", "error", err.Error())
				return
			}
			log.Info("removed this replica's service account key")
		}()
	}

	sink, err := newSink(cfg, awsCfg, log)
	if err != nil {
		log.Error("invalid sink configuration", "error", err.Error())
		return exitConfig
	}

	var runners []*runner
	for _, name := range names(cfg.CplnAudit) {
		r, err := cplnAuditRunner(cfg, name, owner, statePrefix, sink, state, hb, log)
		if err != nil {
			log.Error("invalid audit API configuration", "error", err.Error())
			return exitConfig
		}
		runners = append(runners, r)
	}
	for _, name := range names(cfg.K8sAudit) {
		r, err := k8sAuditRunner(cfg, name, owner, statePrefix, sink, state, hb, log)
		if err != nil {
			log.Error("invalid logs API configuration", "error", err.Error())
			return exitConfig
		}
		runners = append(runners, r)
	}

	var wg sync.WaitGroup
	for _, r := range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.loop(ctx, cfg.Interval)
		}()
	}
	wg.Wait()
	log.Info("shipper stopped")
	return exitOK
}

func names(s config.Source) []string {
	if !s.Enabled {
		return nil
	}
	return s.Names
}

func bucketStore(awsCfg aws.Config, b config.Bucket) *objstore.S3 {
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.Region = b.Region })
	return &objstore.S3{Client: client, Bucket: b.Name, KMSKeyID: b.KMSKeyID}
}

func newSink(cfg *config.Config, awsCfg aws.Config, log *slog.Logger) (pipeline.Sink, error) {
	switch cfg.Sink {
	case config.SinkS3:
		return s3sink.New(s3sink.Config{
			Store: bucketStore(awsCfg, cfg.S3), Prefix: cfg.S3.Prefix, Gzip: cfg.Gzip,
			MaxObjectEvents: cfg.MaxObjectEvents, MaxObjectBytes: cfg.MaxObjectBytes, Logger: log,
		}), nil
	case config.SinkSyslog:
		return syslogsink.New(syslogsink.Config{
			Host: cfg.SyslogHost, Port: cfg.SyslogPort, TLS: cfg.SyslogTLS, CAFile: cfg.SyslogCAFile,
			Framing: cfg.SyslogFraming, Facility: cfg.SyslogFacility, Severity: cfg.SyslogSeverity,
			MaxMessageBytes: cfg.SyslogMaxMessageBytes, Timeout: cfg.SyslogTimeout, Logger: log,
		})
	default:
		return otlpsink.New(otlpsink.Config{
			Endpoint: cfg.OTLPEndpoint, Headers: cfg.OTLPHeaders, CAFile: cfg.OTLPCAFile, Gzip: cfg.OTLPGzip,
			Timeout: cfg.OTLPTimeout, Version: version, Logger: log,
		})
	}
}

func basePipeline(cfg *config.Config, src config.Source, rs record.Source, owner, prefix string) pipeline.Config {
	return pipeline.Config{
		Source: rs, Stream: cfg.Stream, Prefix: prefix,
		StartTime: src.StartTime, InitialLookback: src.InitialLookback, EndTime: src.EndTime,
		SettleDelay: src.SettleDelay, Overlap: src.Overlap, PageSize: src.PageSize,
		MaxBatchEvents: cfg.MaxBatchEvents, MaxBatchBytes: cfg.MaxBatchBytes,
		LeaseTTL: cfg.LeaseTTL, MaxRunDuration: cfg.CycleBudget, DrainTimeout: cfg.DrainTimeout, Owner: owner,
		ExclusiveState: cfg.State == config.StateVolumeSet,
	}
}

func cplnAuditRunner(cfg *config.Config, name, owner, prefix string, sink pipeline.Sink, state objstore.Store, hb *heartbeat, log *slog.Logger) (*runner, error) {
	rs := record.Source{Kind: record.KindCplnAudit, Org: cfg.Org, Name: name}
	log = log.With("source", rs.Kind, "context", name)
	api, err := auditapi.New(auditapi.Config{
		Endpoint: cfg.AuditEndpoint, Org: cfg.Org, Context: name, Token: cfg.Key,
		MinInterval: time.Duration(float64(time.Second) / cfg.MaxRPS), Logger: log,
	})
	if err != nil {
		return nil, err
	}
	pc := basePipeline(cfg, cfg.CplnAudit, rs, owner, prefix)
	pc.Resolution, pc.Pageable = time.Millisecond, true
	pc.InitialQueryWindow, pc.MaxQueryWindow = time.Hour, 24*time.Hour
	return newRunner(pc, api, sink, state, hb, log), nil
}

func k8sAuditRunner(cfg *config.Config, name, owner, prefix string, sink pipeline.Sink, state objstore.Store, hb *heartbeat, log *slog.Logger) (*runner, error) {
	rs := record.Source{Kind: record.KindK8sAudit, Org: cfg.Org, Name: name}
	log = log.With("source", rs.Kind, "cluster", name)
	api, err := lokiapi.New(lokiapi.Config{
		Endpoint: cfg.LogsEndpoint, DiscoveryURL: cfg.DiscoveryURL, Org: cfg.Org, Cluster: name,
		Pipeline: cfg.K8sPipeline, Token: cfg.Key, MinInterval: 100 * time.Millisecond, Logger: log,
	})
	if err != nil {
		return nil, err
	}
	pc := basePipeline(cfg, cfg.K8sAudit, rs, owner, prefix)
	pc.Resolution, pc.Pageable = time.Nanosecond, false
	pc.InitialQueryWindow, pc.MaxQueryWindow = time.Minute, lokiapi.MaxWindow
	return newRunner(pc, api, sink, state, hb, log), nil
}

type runner struct {
	p    *pipeline.Pipeline
	kind string
	name string
	beat func()
	log  *slog.Logger
}

func newRunner(pc pipeline.Config, src pipeline.Source, sink pipeline.Sink, state objstore.Store, hb *heartbeat, log *slog.Logger) *runner {
	r := &runner{kind: pc.Source.Kind, name: pc.Source.Name, log: log}
	beatName := strings.NewReplacer("/", "_", "=", "-").Replace(pc.Source.Partition())
	r.beat = func() { hb.touch(beatName, log) }
	pc.OnProgress = r.beat
	r.p = pipeline.New(pc, src, sink, state, log, time.Now)
	return r
}

// loop runs a cycle every interval. A cycle that takes longer is followed at once, so a backlog is worked off
// without overlapping cycles.
func (r *runner) loop(ctx context.Context, interval time.Duration) {
	r.beat()
	for ctx.Err() == nil {
		started := time.Now()
		res, err := r.p.Run(ctx)
		r.beat()
		attrs := []any{
			"status", res.Status, "batches", res.Batches, "events", res.Events, "writes", res.Writes,
			"bytes", res.Bytes, "queries", res.Queries, "watermark", res.Watermark,
			"lag_seconds", int64(res.Lag.Seconds()), "duration_ms", time.Since(started).Milliseconds(),
		}
		wait := interval - time.Since(started)
		switch {
		case err != nil && ctx.Err() != nil:
			r.log.Info("cycle stopped", attrs...)
			return
		case err != nil:
			r.log.Error("cycle failed, the next one resumes from the checkpoint", append(attrs, "error", err.Error(), "hint", failureHint(err, r.kind, r.name))...)
			wait = max(wait, 10*time.Second)
		case res.Status == pipeline.StatusSkipped:
			r.log.Info("cycle skipped: another replica holds the checkpoint lease", append(attrs, "lease_owner", res.LeaseOwner)...)
		case res.Status == pipeline.StatusBudgetExhausted:
			r.log.Info("cycle reached its budget, continuing", attrs...)
			wait = 0
		default:
			r.log.Info("cycle finished", attrs...)
		}
		if err := r.sleep(ctx, wait); err != nil {
			return
		}
	}
}

// beatEvery is how often a waiting loop refreshes its heartbeat.
var beatEvery = time.Minute

// sleep waits between cycles and keeps the heartbeat fresh, since a waiting loop is not a hung one.
func (r *runner) sleep(ctx context.Context, d time.Duration) error {
	for d > 0 {
		step := min(d, beatEvery)
		if err := backoff.Sleep(ctx, step); err != nil {
			return err
		}
		r.beat()
		d -= step
	}
	return ctx.Err()
}

func credentialsHint(cfg *config.Config) string {
	if cfg.AWS.Mode == awsauth.ModeIdentity {
		return "the workload identity needs AWS cloud access (a cloud account plus a role or policies)"
	}
	if cfg.AWS.RoleARN != "" {
		return "check the access keys in the secret, that they may call sts:AssumeRole on the role, and the role's trust policy and external ID"
	}
	return "check the access keys in the secret"
}

func failureHint(err error, kind, name string) string {
	var authErr *httpx.AuthError
	switch {
	case errors.As(err, &authErr) && authErr.Service == "logs API":
		return "the service account needs readLogs on the org"
	case errors.As(err, &authErr) && authErr.Service == "audit API":
		return fmt.Sprintf("the service account needs readAudit on auditctx/%s, and its key must still exist", name)
	case errors.As(err, &authErr):
		return "the sink rejected the credentials; check the OTLP auth header secret"
	case errors.Is(err, objstore.ErrAccessDenied):
		return "the AWS principal lacks S3 (or KMS) permissions on the bucket, or the state volume is not writable; see Permissions in the README"
	case errors.Is(err, pipeline.ErrStateInvalid):
		return "the checkpoint is unreadable; progress was not reset. See Recovery in the README"
	case errors.Is(err, pipeline.ErrLostLease):
		return "another replica took over the checkpoint; nothing was committed past what this one delivered"
	case errors.Is(err, pipeline.ErrUnstableWindow):
		return "more records share one timestamp than a page holds; raise the page size"
	case kind == record.KindK8sAudit && strings.Contains(err.Error(), "logs API"):
		return "check the logs endpoint and that the cluster's audit logs are enabled (mk8s logs add-on, auditEnabled)"
	default:
		return "transient errors resolve on a later cycle; the checkpoint only moves after records are delivered"
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "0000"
	}
	return hex.EncodeToString(b)
}
