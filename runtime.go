package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/config"
	"github.com/controlplane-com/cpln-audit-shipper/internal/filestore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/sakey"
)

// heartbeat keeps one file per pipeline. The liveness probe fails when any of them is older than the maximum age,
// which only happens when a loop hangs: a failing cycle still touches its file.
type heartbeat struct{ dir string }

func (h *heartbeat) touch(name string, log *slog.Logger) {
	if err := os.WriteFile(filepath.Join(h.dir, name), nil, 0o640); err != nil {
		log.Warn("cannot write the heartbeat", "error", err.Error())
	}
}

func (h *heartbeat) remove(name string) { _ = os.Remove(filepath.Join(h.dir, name)) }

func healthcheck(get func(string) string, now time.Time) int {
	dir := get("HEARTBEAT_DIR")
	if dir == "" {
		dir = "/tmp/heartbeat"
	}
	maxAge := 30 * time.Minute
	if v := get("HEARTBEAT_MAX_AGE"); v != "" {
		if d, err := config.ParseDuration(v); err == nil && d > 0 {
			maxAge = d
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no heartbeat yet")
		return 1
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			return 1
		}
		if age := now.Sub(info.ModTime()); age > maxAge {
			fmt.Fprintf(os.Stderr, "%s has not made progress for %s\n", e.Name(), age.Round(time.Second))
			return 1
		}
	}
	return 0
}

// setMemoryLimit sets Go's soft memory limit to 80% of the container's, unless GOMEMLIMIT is set, so the
// collector works harder before the container is killed.
func setMemoryLimit(log *slog.Logger) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		limit, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil || limit <= 0 || limit >= 1<<60 {
			return
		}
		debug.SetMemoryLimit(limit * 8 / 10)
		log.Info("memory limit set", "container_bytes", limit, "go_limit_bytes", limit*8/10)
		return
	}
}

// checkSingleLocation reads the workload's GVC with its own token, which the Control Plane API accepts through
// the workload's sidecar, and fails when the GVC has more than one location.
func checkSingleLocation(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if cfg.CplnEndpoint == "" || cfg.CplnToken == "" || cfg.GVC == "" {
		return errors.New("CPLN_ENDPOINT, CPLN_TOKEN and CPLN_GVC are not set, so the GVC's locations cannot be checked")
	}
	target := strings.TrimRight(cfg.CplnEndpoint, "/") + "/org/" + url.PathEscape(cfg.Org) + "/gvc/" + url.PathEscape(cfg.GVC)
	c := &httpx.Client{Service: "Control Plane API", Logger: log, Timeout: 30 * time.Second}
	body, err := c.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", cfg.CplnToken)
		return req, nil
	})
	if err != nil {
		return fmt.Errorf("reading GVC %s (the identity needs view on it): %w", cfg.GVC, err)
	}
	var gvc struct {
		Spec struct {
			StaticPlacement struct {
				LocationLinks []string `json:"locationLinks"`
			} `json:"staticPlacement"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &gvc); err != nil {
		return fmt.Errorf("reading GVC %s: %w", cfg.GVC, err)
	}
	if n := len(gvc.Spec.StaticPlacement.LocationLinks); n > 1 {
		return fmt.Errorf("GVC %s has %d locations", cfg.GVC, n)
	}
	return nil
}

// acquireLock takes the state volume's lock, waiting while another replica holds it. It fails closed: a volume
// that cannot lock files is a configuration error, since nothing else would keep two replicas apart.
func acquireLock(ctx context.Context, cfg *config.Config, hb *heartbeat, log *slog.Logger) (*filestore.Lock, int) {
	const waiting = "state-lock-wait"
	defer hb.remove(waiting)
	for {
		lock, err := filestore.Acquire(cfg.StateDir)
		switch {
		case err == nil:
			log.Info("state lock acquired", "dir", cfg.StateDir)
			return lock, exitOK
		case errors.Is(err, filestore.ErrLocked):
			hb.touch(waiting, log)
			log.Info("another replica holds the state lock; waiting", "dir", cfg.StateDir)
			if backoff.Sleep(ctx, 15*time.Second) != nil {
				return nil, exitOK
			}
		case errors.Is(err, filestore.ErrLockUnsupported):
			log.Error("the state volume cannot lock files; refusing to run without the lock", "error", err.Error())
			return nil, exitConfig
		default:
			log.Error("cannot open the state lock", "error", err.Error(), "hint", "the volume must be writable by the container's group (securityOptions.filesystemGroupId)")
			return nil, exitFailed
		}
	}
}

// mintKey adds this replica's service account key, retrying for a few minutes: on install, the template's service
// account can be created after the workload has started.
func mintKey(ctx context.Context, m *sakey.Minter, hb *heartbeat, log *slog.Logger) (*sakey.Key, error) {
	const waiting = "service-account-wait"
	defer hb.remove(waiting)
	deadline := time.Now().Add(5 * time.Minute)
	for {
		key, err := m.Mint(ctx)
		if err == nil || ctx.Err() != nil || time.Now().After(deadline) {
			return key, err
		}
		hb.touch(waiting, log)
		log.Warn("cannot add a key to the service account yet; retrying", "error", err.Error())
		if err := backoff.Sleep(ctx, 15*time.Second); err != nil {
			return nil, err
		}
	}
}
