# cpln-audit-shipper

Ships a Control Plane org's audit logs to a destination you own, continuously and incrementally:

- **The Control Plane audit trail**: who did what to which resource in the org, read from the audit API per audit context.
- **Kubernetes audit logs of mk8s clusters**: the API server audit log of each cluster, read from the org's logs (`{cluster_name="<cluster>", job="audit"}`).

Destinations: **Amazon S3** (JSON Lines), **syslog** over TCP or TLS (RFC 5424, in the layout of Control Plane org logging), or an **OpenTelemetry** collector (OTLP/HTTP with JSON).

It runs as a long-lived Control Plane workload, one pipeline per audit context and per cluster, each with its own checkpoint in S3 or on a volume set. Restarts, upgrades, crashes and suspensions continue where each stream stopped. The usual way to run it is the `cpln-audit-shipper` template in the [Control Plane template catalog](https://github.com/controlplane-com/templates), which creates the workload, identity, policies and volume set; its README covers setup, delivery guarantees and troubleshooting.

## How it works

Each pipeline runs a cycle every `INTERVAL`, or at once after a cycle that ran longer:

1. Takes the stream's lease in its checkpoint, or skips the cycle when another replica holds it. A new stream saves its start before anything is delivered.
2. Reads from *watermark − overlap* up to *now − settle delay*, one window at a time, and drops the IDs it already delivered. A window is accepted only when it fits in one page (the audit API orders tied timestamps differently on every call), so full windows are narrowed and read again.
3. Records the batch as pending, delivers it, then moves the watermark, all with conditional writes, so a replica that lost its lease can never overwrite another's progress.

**Settle delay** is how old a record must be before a cycle reads it, so records still on their way are left for the next cycle. **Overlap** is how far behind its checkpoint each cycle reads again, skipping what it already shipped, to catch records that arrived late. A record is shipped as long as it becomes readable within settle delay plus overlap of its own timestamp.

Delivery is at least once. Every record keeps its ID (`id`, or `auditID` and `stage`), so duplicates can be dropped downstream. S3 replays an interrupted batch to the same object names. Syslog and OTLP resend at most one batch.

## Configuration

Everything is read from environment variables; the template sets them. Invalid settings are all reported at once and the process exits with code 2.

| Variable | Default | |
|---|---|---|
| `SERVICE_ACCOUNT_NAME` | one of these two | A service account with `readAudit` on the audit contexts and, for Kubernetes audit logs, `readLogs` on the org. Each replica adds a key of its own to it at startup, through the Control Plane API with the workload's `CPLN_TOKEN` (the identity needs `addKey`, `edit` and `view` on the service account), keeps the key in memory only, and removes it when it stops. A starting replica removes keys its location left more than 30 minutes ago, after a crash. A service account holds at most 10 keys. |
| `SERVICE_ACCOUNT_KEY` | one of these two | A key of such a service account, for example from a secret. The audit and logs APIs do not accept a workload's own `CPLN_TOKEN`, so one of the two is needed. |
| `STREAM` | `default` | Names this export; part of every checkpoint and object name |
| `INTERVAL` | `5m` | Time between the starts of two cycles of each stream (10s to 24h) |
| `AUDIT_ENABLED` | `true` | The Control Plane audit trail |
| `AUDIT_CONTEXTS` | `cpln` | Comma-separated audit contexts |
| `AUDIT_START_TIME`, `AUDIT_END_TIME` | empty | RFC 3339 bounds of a new stream (an end time makes a backfill stream) |
| `AUDIT_INITIAL_LOOKBACK` | `24h` | Start of a new stream when no start time is set |
| `AUDIT_SETTLE_DELAY`, `AUDIT_OVERLAP` | `1m`, `15m` | See [How it works](#how-it-works) |
| `AUDIT_PAGE_SIZE`, `AUDIT_MAX_RPS`, `AUDIT_ENDPOINT` | `1000`, `10`, `https://audit.cpln.io` | |
| `K8S_AUDIT_ENABLED` | `false` | Kubernetes audit logs of mk8s clusters |
| `K8S_AUDIT_CLUSTERS` | | Comma-separated cluster names |
| `K8S_AUDIT_PIPELINE` | empty | LogQL appended to the selector, starting with `\|`, such as `\| verb != "get"` |
| `K8S_AUDIT_START_TIME`, `K8S_AUDIT_END_TIME` | empty | As for the audit trail |
| `K8S_AUDIT_INITIAL_LOOKBACK`, `K8S_AUDIT_SETTLE_DELAY`, `K8S_AUDIT_OVERLAP` | `1h`, `2m`, `2m` | |
| `K8S_AUDIT_PAGE_SIZE`, `LOGS_ENDPOINT`, `DISCOVERY_URL` | `5000`, from discovery, `https://api.cpln.io/discovery` | |
| `SINK_TYPE` | required | `s3`, `syslog` or `otlp` |
| `S3_BUCKET`, `S3_REGION`, `S3_PREFIX`, `S3_GZIP`, `S3_KMS_KEY_ID` | `S3_PREFIX=cpln-audit`, `S3_GZIP=true` | S3 destination |
| `MAX_OBJECT_EVENTS`, `MAX_OBJECT_BYTES` | `10000`, 32 MiB | S3 object limits |
| `SYSLOG_HOST`, `SYSLOG_PORT`, `SYSLOG_TLS`, `SYSLOG_TLS_CA_FILE` | port `6514`, TLS `true` | A CA file replaces the system CAs |
| `SYSLOG_FRAMING`, `SYSLOG_FACILITY`, `SYSLOG_SEVERITY`, `SYSLOG_MAX_MESSAGE_BYTES`, `SYSLOG_TIMEOUT` | `newline`, `1`, `7`, 32 KiB, `60s` | |
| `OTLP_ENDPOINT`, `OTLP_HEADERS`, `OTLP_AUTH_HEADER`, `OTLP_AUTH_VALUE`, `OTLP_TLS_CA_FILE`, `OTLP_GZIP`, `OTLP_TIMEOUT` | gzip `true`, `30s` | `/v1/logs` is appended to the endpoint; headers are `name=value,…` |
| `STATE_BACKEND` | `s3` | `s3` or `volumeSet` (a single-location GVC only) |
| `STATE_S3_BUCKET`, `STATE_S3_REGION`, `STATE_S3_PREFIX`, `STATE_S3_KMS_KEY_ID` | the S3 destination's | Checkpoint bucket |
| `STATE_DIR` | `/state` | Checkpoint directory for `volumeSet` |
| `AWS_AUTH_MODE` | | `identity` (default credential chain) or `secret` |
| `AWS_SOURCE_ACCESS_KEY_ID`, `AWS_SOURCE_SECRET_ACCESS_KEY`, `AWS_SOURCE_SESSION_TOKEN` | | With `secret` |
| `AWS_ASSUME_ROLE_ARN`, `AWS_ASSUME_ROLE_EXTERNAL_ID`, `AWS_ASSUME_ROLE_SESSION_NAME`, `AWS_ASSUME_ROLE_DURATION` | session `cpln-audit-shipper`, `1h` | Optional role to assume with the keys |
| `LEASE_TTL`, `CYCLE_BUDGET`, `DRAIN_TIMEOUT` | `5m`, `30m`, `60s` | |
| `MAX_BATCH_EVENTS`, `MAX_BATCH_BYTES` | `10000`, 32 MiB | |
| `HEARTBEAT_DIR`, `HEARTBEAT_MAX_AGE`, `LOG_LEVEL` | `/tmp/heartbeat`, `30m`, `info` | |

`cpln-audit-shipper healthcheck` exits non-zero when a pipeline has made no progress for `HEARTBEAT_MAX_AGE`; use it as the liveness probe. The Go memory limit is set to 80% of the container's unless `GOMEMLIMIT` is set.

## Layout

| Path | What |
|---|---|
| `main.go` | Wiring, one loop per pipeline, signal handling, exit codes |
| `runtime.go` | Heartbeats and `healthcheck`, the memory limit, the single-location check and lock for volume set state |
| `internal/sakey` | Adds this replica's key to the service account at startup and removes it on stop |
| `internal/pipeline` | The core: checkpoint, lease, windowing, batching, commit order |
| `internal/auditapi`, `internal/lokiapi` | Sources |
| `internal/sink/s3sink`, `syslogsink`, `otlpsink` | Sinks |
| `internal/objstore`, `internal/filestore` | Checkpoint stores: S3 with conditional writes, files with `flock` |
| `internal/config`, `internal/record`, `internal/httpx`, `internal/awsauth`, `internal/backoff` | Shared pieces |
| `internal/fakes` | In-memory sources, bucket and sink for tests |

## Develop

```bash
make test        # go vet + go test -race
make build       # bin/cpln-audit-shipper
```

The tests run the pipeline against fakes that reproduce each source's paging behaviour and S3's conditional writes. They cover ties at page boundaries, late events, restarts, concurrent replicas, failed and partial deliveries, crashes between delivery and commit, unreadable checkpoints, cancellation and draining, and both checkpoint stores. The syslog tests run real TCP and TLS listeners.

To try a build in an org before a release: `make cpln-image ORG=my-org TAG=v1.0.0-rc1`, then point the template's `image` at `//image/cpln-audit-shipper:v1.0.0-rc1`.

## Release

Push a tag such as `v1.0.0`. The `Publish Docker Image` workflow tests and pushes `ghcr.io/controlplane-com/cpln-build/cpln-audit-shipper:v1.0.0` for linux/amd64 and linux/arm64. Then point the template's `image` at the new tag in a new template version.
