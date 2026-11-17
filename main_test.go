package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/config"
)

func TestHealthcheckFailsOnlyWhenAPipelineStopsMakingProgress(t *testing.T) {
	dir := t.TempDir()
	get := func(k string) string {
		return map[string]string{"HEARTBEAT_DIR": dir, "HEARTBEAT_MAX_AGE": "30m"}[k]
	}
	now := time.Now()
	if healthcheck(get, now) == 0 {
		t.Fatal("healthy without any heartbeat")
	}
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if healthcheck(get, now) != 0 {
		t.Fatal("unhealthy with fresh heartbeats")
	}
	old := now.Add(-31 * time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "b"), old, old); err != nil {
		t.Fatal(err)
	}
	if healthcheck(get, now) == 0 {
		t.Fatal("healthy although one pipeline stopped making progress")
	}
}

func TestSingleLocationCheckReadsTheGVCWithTheWorkloadToken(t *testing.T) {
	locations := `["/org/acme/location/aws-eu-central-1"]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/org/acme/gvc/dev" || r.Header.Get("Authorization") != "w.token" {
			t.Errorf("request %s with %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"spec":{"staticPlacement":{"locationLinks":` + locations + `}}}`))
	}))
	defer srv.Close()
	cfg := &config.Config{Org: "acme", GVC: "dev", CplnEndpoint: srv.URL, CplnToken: "w.token"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := checkSingleLocation(context.Background(), cfg, log); err != nil {
		t.Fatal(err)
	}
	locations = `["/org/acme/location/a", "/org/acme/location/b"]`
	if err := checkSingleLocation(context.Background(), cfg, log); err == nil || !strings.Contains(err.Error(), "2 locations") {
		t.Fatalf("err = %v, want a two-location refusal", err)
	}
	if err := checkSingleLocation(context.Background(), &config.Config{Org: "acme"}, log); err == nil {
		t.Fatal("passed without the workload's API access")
	}
}

func TestWaitingBetweenCyclesKeepsTheHeartbeatFresh(t *testing.T) {
	beats := 0
	r := &runner{beat: func() { beats++ }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.sleep(ctx, time.Hour); err == nil {
		t.Fatal("a cancelled wait returned no error")
	}
	old := beatEvery
	beatEvery = 10 * time.Millisecond
	t.Cleanup(func() { beatEvery = old })
	if err := r.sleep(context.Background(), 55*time.Millisecond); err != nil || beats < 5 {
		t.Fatalf("a 55ms wait: err %v, %d beats, want one per 10ms", err, beats)
	}
}
