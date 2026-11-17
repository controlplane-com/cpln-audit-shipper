package pipeline

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/fakes"
	"github.com/controlplane-com/cpln-audit-shipper/internal/filestore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/objstore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
	"github.com/controlplane-com/cpln-audit-shipper/internal/sink/s3sink"
)

var t0 = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)

const (
	pipelineID = "org=acme/source=cpln-audit/context=cpln/sink=s3/stream=default"
	stateKey   = "audit/state/" + pipelineID + "/checkpoint.json"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harness struct {
	t     *testing.T
	api   *fakes.Audit
	store *fakes.Store
	clock *clock
	cfg   Config
	s3    s3sink.Config
}

func newHarness(t *testing.T) *harness {
	return &harness{
		t:     t,
		api:   fakes.NewAudit(42),
		store: fakes.NewStore(),
		clock: &clock{t: t0},
		cfg: Config{
			Source: record.Source{Kind: record.KindCplnAudit, Org: "acme", Name: "cpln"},
			Stream: "default", Prefix: "audit",
			InitialLookback: 24 * time.Hour, SettleDelay: time.Minute, Overlap: 10 * time.Minute,
			PageSize: 50, Resolution: time.Millisecond, Pageable: true,
			InitialQueryWindow: time.Hour, MaxQueryWindow: 24 * time.Hour,
			MaxBatchEvents: 100000, LeaseTTL: 5 * time.Minute, MaxRunDuration: time.Hour, Owner: "runner-a",
		},
		s3: s3sink.Config{Prefix: "audit", Gzip: true, MaxObjectEvents: 100000, MaxObjectBytes: 8 << 20},
	}
}

// sink writes to store, which is the harness bucket or a wrapper of it.
func (h *harness) sink(store objstore.Store) *s3sink.Sink {
	c := h.s3
	c.Store = store
	return s3sink.New(c)
}

func (h *harness) pipeline(owner string) *Pipeline {
	cfg := h.cfg
	cfg.Owner = owner
	log := slog.New(slog.NewTextHandler(h.t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	return New(cfg, h.api, h.sink(h.store), h.store, log, h.clock.Now)
}

func (h *harness) run(owner string) (Result, error) {
	return h.pipeline(owner).Run(context.Background())
}

func (h *harness) mustRun(owner string) Result {
	h.t.Helper()
	res, err := h.run(owner)
	if err != nil {
		h.t.Fatalf("run %s: %v", owner, err)
	}
	return res
}

func (h *harness) state() *State {
	h.t.Helper()
	return h.stateAt(stateKey)
}

func (h *harness) stateAt(key string) *State {
	h.t.Helper()
	body, _, err := h.store.Get(context.Background(), key)
	if err != nil {
		h.t.Fatalf("reading state: %v", err)
	}
	var st State
	if err := json.Unmarshal(body, &st); err != nil {
		h.t.Fatalf("decoding state: %v", err)
	}
	return &st
}

// exported counts how many times each event ID appears across all data objects.
func (h *harness) exported() map[string]int {
	h.t.Helper()
	counts := map[string]int{}
	for _, key := range h.store.Keys("audit/data/") {
		for _, line := range readLines(h.t, key, h.store.Body(key)) {
			var ev struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(line, &ev); err != nil || ev.ID == "" {
				h.t.Fatalf("object %s holds an invalid line %q", key, line)
			}
			counts[ev.ID]++
		}
	}
	return counts
}

func readLines(t *testing.T, key string, body []byte) [][]byte {
	t.Helper()
	var r io.Reader = bytes.NewReader(body)
	if strings.HasSuffix(key, ".gz") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			t.Fatalf("object %s is not gzip: %v", key, err)
		}
		r = zr
	}
	var lines [][]byte
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		lines = append(lines, append([]byte(nil), sc.Bytes()...))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", key, err)
	}
	return lines
}

func assertExactlyOnce(t *testing.T, got map[string]int, events []record.Record) {
	t.Helper()
	want := map[string]bool{}
	for _, ev := range events {
		want[ev.ID] = true
		if got[ev.ID] != 1 {
			t.Errorf("event %s exported %d times, want 1", ev.ID, got[ev.ID])
		}
	}
	for id, n := range got {
		if !want[id] {
			t.Errorf("unexpected event %s exported %d times", id, n)
		}
	}
}

// spread makes n events evenly spaced in [from, to), in groups of tie events sharing one timestamp.
func spread(prefix string, n, tie int, from, to time.Time) []record.Record {
	groups := (n + tie - 1) / tie
	step := to.Sub(from) / time.Duration(groups)
	var out []record.Record
	for i := 0; i < n; i++ {
		ts := from.Add(step * time.Duration(i/tie)).Truncate(time.Millisecond)
		out = append(out, fakes.Event(fmt.Sprintf("%s-%05d", prefix, i), ts))
	}
	return out
}

func TestEmptyWindowsAdvanceWithoutDataObjects(t *testing.T) {
	h := newHarness(t)
	res := h.mustRun("runner-a")
	if res.Status != StatusCaughtUp || res.Events != 0 || res.Writes != 0 {
		t.Fatalf("first run = %+v, want caught-up with nothing exported", res)
	}
	if want := t0.Add(-time.Minute); !h.state().Watermark.Equal(want) {
		t.Fatalf("watermark = %s, want %s", h.state().Watermark, want)
	}
	h.clock.Advance(5 * time.Minute)
	h.mustRun("runner-a")
	if keys := h.store.Keys("audit/data/"); len(keys) != 0 {
		t.Fatalf("empty windows wrote data objects: %v", keys)
	}
	st := h.state()
	if want := t0.Add(4 * time.Minute); !st.Watermark.Equal(want) {
		t.Fatalf("watermark = %s, want %s", st.Watermark, want)
	}
	if st.Lease != nil || st.Pending != nil {
		t.Fatalf("state after a clean run holds lease=%v pending=%v", st.Lease, st.Pending)
	}
}

func TestFirstRunStartsAtStartTimeAndLaterRunsIgnoreIt(t *testing.T) {
	h := newHarness(t)
	h.cfg.StartTime = t0.Add(-20 * time.Minute)
	before := fakes.Event("before", t0.Add(-25*time.Minute))
	atStart := fakes.Event("at-start", t0.Add(-20*time.Minute))
	after := fakes.Event("after", t0.Add(-5*time.Minute))
	h.api.Add(before, atStart, after)

	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), []record.Record{atStart, after})

	h.cfg.StartTime = t0.Add(-2 * time.Hour)
	h.clock.Advance(5 * time.Minute)
	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), []record.Record{atStart, after})
}

func TestPaginationAndTiedTimestampsExportEveryEventOnce(t *testing.T) {
	h := newHarness(t)
	events := spread("e", 3000, 30, t0.Add(-3*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	res := h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), events)
	if res.Events != len(events) {
		t.Fatalf("result counted %d events, want %d", res.Events, len(events))
	}
}

func TestMoreTiesThanAPageInOneMillisecond(t *testing.T) {
	h := newHarness(t)
	h.api.StableTies = true
	ts := t0.Add(-30 * time.Minute)
	var events []record.Record
	for i := 0; i < 180; i++ {
		events = append(events, fakes.Event(fmt.Sprintf("tie-%03d", i), ts))
	}
	events = append(events, fakes.Event("next", ts.Add(time.Millisecond)), fakes.Event("prev", ts.Add(-time.Millisecond)))
	h.api.Add(events...)
	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), events)
}

func TestLateEventsWithinOverlapAndBoundaryTiesAreExportedOnce(t *testing.T) {
	h := newHarness(t)
	early := spread("early", 40, 4, t0.Add(-50*time.Minute), t0.Add(-5*time.Minute))
	h.api.Add(early...)
	h.mustRun("runner-a")
	watermark := h.state().Watermark

	late := fakes.Event("late", watermark.Add(-6*time.Minute))
	onBoundary := fakes.Event("on-boundary", watermark)
	tiedWithExported := fakes.Event("tied-with-exported", early[len(early)-1].Time)
	h.api.Add(late, onBoundary, tiedWithExported)

	h.clock.Advance(5 * time.Minute)
	res := h.mustRun("runner-a")
	if res.Events != 3 {
		t.Fatalf("second run exported %d events, want the 3 late ones", res.Events)
	}
	assertExactlyOnce(t, h.exported(), append(early, late, onBoundary, tiedWithExported))
}

func TestRestartResumesFromCheckpoint(t *testing.T) {
	h := newHarness(t)
	first := spread("a", 200, 2, t0.Add(-2*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(first...)
	h.mustRun("runner-a")

	second := spread("b", 50, 1, t0, t0.Add(9*time.Minute))
	h.api.Add(second...)
	h.clock.Advance(15 * time.Minute)
	res := h.mustRun("runner-b")
	if res.Events != len(second) {
		t.Fatalf("restarted run exported %d events, want only the %d new ones", res.Events, len(second))
	}
	assertExactlyOnce(t, h.exported(), append(first, second...))
}

func TestRecentIDsArePrunedToTheOverlap(t *testing.T) {
	h := newHarness(t)
	h.api.Add(spread("a", 100, 1, t0.Add(-3*time.Hour), t0.Add(-2*time.Minute))...)
	h.mustRun("runner-a")
	st := h.state()
	cut := st.Watermark.Add(-h.cfg.Overlap)
	if len(st.Recent) == 0 {
		t.Fatal("recent IDs are empty although events fall inside the overlap")
	}
	for id, ts := range st.Recent {
		if ts.Before(cut) {
			t.Errorf("recent keeps %s at %s, before the overlap start %s", id, ts, cut)
		}
	}
}

// barrierStore holds every runner at its first checkpoint read until all of them have read it.
type barrierStore struct {
	*fakes.Store
	wg    sync.WaitGroup
	mu    sync.Mutex
	gates int
}

func (b *barrierStore) Get(ctx context.Context, key string) ([]byte, string, error) {
	body, etag, err := b.Store.Get(ctx, key)
	b.mu.Lock()
	gated := b.gates < 2
	b.gates++
	b.mu.Unlock()
	if gated {
		b.wg.Done()
		b.wg.Wait()
	}
	return body, etag, err
}

func TestConcurrentRunnersExportEachEventOnce(t *testing.T) {
	h := newHarness(t)
	events := spread("c", 500, 5, t0.Add(-2*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(events...)

	bs := &barrierStore{Store: h.store}
	bs.wg.Add(2)
	results := make([]Result, 2)
	errs := make([]error, 2)
	var done sync.WaitGroup
	for i, owner := range []string{"runner-a", "runner-b"} {
		done.Add(1)
		go func() {
			defer done.Done()
			cfg := h.cfg
			cfg.Owner = owner
			ex := New(cfg, h.api, h.sink(bs), bs, slog.New(slog.NewTextHandler(io.Discard, nil)), h.clock.Now)
			results[i], errs[i] = ex.Run(context.Background())
		}()
	}
	done.Wait()

	skipped := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("runner %d: %v", i, errs[i])
		}
		if results[i].Status == StatusSkipped {
			skipped++
		}
	}
	if skipped != 1 {
		t.Fatalf("%d runners skipped, want exactly 1: %+v", skipped, results)
	}
	assertExactlyOnce(t, h.exported(), events)
}

func TestLeaseHeldByAnotherRunnerSkipsUntilItExpires(t *testing.T) {
	h := newHarness(t)
	held := &State{
		SchemaVersion: stateSchemaVersion, Pipeline: pipelineID,
		Floor: t0.Add(-time.Hour), Watermark: t0.Add(-time.Hour), Recent: map[string]time.Time{},
		Lease: &Lease{Owner: "runner-z", AcquiredAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(4 * time.Minute)},
	}
	body, _ := json.Marshal(held)
	h.store.Set(stateKey, body)
	ev := fakes.Event("x", t0.Add(-30*time.Minute))
	h.api.Add(ev)

	res := h.mustRun("runner-a")
	if res.Status != StatusSkipped || res.LeaseOwner != "runner-z" {
		t.Fatalf("run under a live lease = %+v, want skipped for runner-z", res)
	}
	if len(h.exported()) != 0 {
		t.Fatal("a skipped run exported data")
	}

	h.clock.Advance(5 * time.Minute)
	if res := h.mustRun("runner-a"); res.Status != StatusCaughtUp {
		t.Fatalf("run after the lease expired = %+v, want caught-up", res)
	}
	assertExactlyOnce(t, h.exported(), []record.Record{ev})
}

func TestFailedUploadKeepsCheckpointAndRetryReusesKeys(t *testing.T) {
	h := newHarness(t)
	h.s3.MaxObjectEvents = 30
	events := spread("u", 120, 3, t0.Add(-90*time.Minute), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	floor := t0.Add(-24 * time.Hour)

	dataPuts := 0
	h.store.FailPut = func(key string, _ int) error {
		if strings.Contains(key, "/data/") {
			dataPuts++
			if dataPuts == 3 {
				return errors.New("injected: connection reset")
			}
		}
		return nil
	}
	if _, err := h.run("runner-a"); err == nil {
		t.Fatal("run with a failed upload succeeded")
	}
	st := h.state()
	if !st.Watermark.Equal(floor) || st.Pending == nil {
		t.Fatalf("after a failed upload watermark=%s pending=%v, want %s and a pending batch", st.Watermark, st.Pending, floor)
	}
	if st.Lease != nil {
		t.Fatal("a failed run left its lease behind")
	}
	firstKeys := h.store.Keys("audit/data/")

	h.store.FailPut = nil
	h.clock.Advance(5 * time.Minute)
	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), events)
	for _, k := range firstKeys {
		if !strings.Contains(k, s3sink.CompactTime(floor)+"_"+s3sink.CompactTime(st.Pending.To)) {
			t.Errorf("first attempt wrote %s outside the pending batch bounds", k)
		}
	}
}

func TestCrashAfterUploadBeforeCommitDoesNotDuplicate(t *testing.T) {
	h := newHarness(t)
	h.s3.MaxObjectEvents = 25
	events := spread("k", 100, 2, t0.Add(-90*time.Minute), t0.Add(-2*time.Minute))
	h.api.Add(events...)

	uploaded := false
	h.store.FailPut = func(key string, _ int) error {
		if strings.Contains(key, "/data/") {
			uploaded = true
			return nil
		}
		if uploaded {
			return errors.New("injected: process killed")
		}
		return nil
	}
	if _, err := h.run("runner-a"); err == nil {
		t.Fatal("run that crashed before its commit succeeded")
	}
	st := h.state()
	if st.Pending == nil || st.Lease == nil || st.Lease.Owner != "runner-a" {
		t.Fatalf("crashed run should leave pending batch and its lease: pending=%v lease=%v", st.Pending, st.Lease)
	}
	keysBefore := h.store.Keys("audit/data/")
	if len(keysBefore) == 0 {
		t.Fatal("crashed run uploaded nothing; the scenario needs uploaded objects")
	}

	late := fakes.Event("late-during-crash", st.Watermark.Add(time.Hour))
	h.api.Add(late)
	h.store.FailPut = nil

	if res := h.mustRun("runner-b"); res.Status != StatusSkipped {
		t.Fatalf("run inside the crashed lease = %+v, want skipped", res)
	}
	h.clock.Advance(6 * time.Minute)
	h.mustRun("runner-b")
	assertExactlyOnce(t, h.exported(), append(events, late))
	keysAfter := h.store.Keys("audit/data/")
	for _, k := range keysBefore {
		found := false
		for _, a := range keysAfter {
			found = found || a == k
		}
		if !found {
			t.Errorf("key %s from the crashed attempt vanished", k)
		}
	}
}

func TestUnreadableStateIsNeverReset(t *testing.T) {
	cases := map[string]func(h *harness){
		"access denied": func(h *harness) {
			h.store.FailGet = func(string) error { return fmt.Errorf("%w: 403", objstore.ErrAccessDenied) }
		},
		"corrupt json": func(h *harness) { h.store.Set(stateKey, []byte(`{"schemaVersion": 1, "watermark": `)) },
		"other stream": func(h *harness) {
			body, _ := json.Marshal(State{SchemaVersion: 1, Pipeline: "org=acme/source=cpln-audit/context=cpln/sink=s3/stream=backfill",
				Floor: t0.Add(-time.Hour), Watermark: t0.Add(-time.Hour)})
			h.store.Set(stateKey, body)
		},
		"future schema": func(h *harness) {
			h.store.Set(stateKey, []byte(`{"schemaVersion": 2, "pipeline": "`+pipelineID+`"}`))
		},
		"read error": func(h *harness) {
			h.store.FailGet = func(string) error { return errors.New("injected: timeout") }
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			setup(h)
			before := h.store.Body(stateKey)
			h.api.Add(fakes.Event("x", t0.Add(-30*time.Minute)))
			if _, err := h.run("runner-a"); err == nil {
				t.Fatal("run over unreadable state succeeded")
			}
			if after := h.store.Body(stateKey); !bytes.Equal(before, after) {
				t.Fatalf("state changed from %q to %q", before, after)
			}
			if keys := h.store.Keys("audit/data/"); len(keys) != 0 {
				t.Fatalf("exported %v over unreadable state", keys)
			}
		})
	}
}

func TestAuditFailureDoesNotAdvanceCheckpoint(t *testing.T) {
	h := newHarness(t)
	h.cfg.InitialQueryWindow = 10 * time.Minute
	h.cfg.MaxQueryWindow = 10 * time.Minute
	events := spread("f", 60, 1, t0.Add(-3*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	h.api.Fail = func(_ record.Query, n int) error {
		if n == 5 {
			return errors.New("injected: HTTP 503")
		}
		return nil
	}
	if _, err := h.run("runner-a"); err == nil {
		t.Fatal("run with a failed query succeeded")
	}
	st := h.state()
	if !st.Watermark.Equal(t0.Add(-24*time.Hour)) || st.Pending != nil {
		t.Fatalf("failed query moved the checkpoint: watermark=%s pending=%v", st.Watermark, st.Pending)
	}
	if keys := h.store.Keys("audit/data/"); len(keys) != 0 {
		t.Fatalf("failed query still uploaded %v", keys)
	}
	h.api.Fail = nil
	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), events)
}

var keyPattern = regexp.MustCompile(`^audit/data/org=acme/source=cpln-audit/context=cpln/year=2026/month=11/day=16/hour=(\d\d)/default_\d{8}T\d{9}Z_\d{8}T\d{9}Z_(\d{4})\.jsonl\.gz$`)

func TestObjectsSplitByHourCountAndSize(t *testing.T) {
	h := newHarness(t)
	h.s3.MaxObjectEvents = 7
	events := spread("o", 30, 1, t0.Add(-90*time.Minute), t0.Add(-2*time.Minute))
	big := fakes.Event("big", t0.Add(-3*time.Minute))
	big.Raw = []byte(`{"id":"big","eventTime":"` + big.Time.Format(time.RFC3339Nano) + `","pad":"` + strings.Repeat("x", 3000) + `"}`)
	h.s3.MaxObjectBytes = 2048
	h.api.Add(append(events, big)...)
	h.mustRun("runner-a")

	keys := h.store.Keys("audit/data/")
	hours := map[string]int{}
	for _, k := range keys {
		m := keyPattern.FindStringSubmatch(k)
		if m == nil {
			t.Fatalf("unexpected key layout %s", k)
		}
		hours[m[1]]++
		lines := readLines(t, k, h.store.Body(k))
		if len(lines) > 7 {
			t.Errorf("%s holds %d events, limit 7", k, len(lines))
		}
		opts := h.store.Options(k)
		if opts.ContentType != "application/gzip" || opts.Metadata["event-count"] != fmt.Sprint(len(lines)) {
			t.Errorf("%s has content type %q and event-count %q for %d lines", k, opts.ContentType, opts.Metadata["event-count"], len(lines))
		}
		if opts.IfMatch != "" || opts.IfNoneMatch {
			t.Errorf("data object %s was written conditionally; retries must overwrite", k)
		}
	}
	if hours["08"] == 0 || hours["09"] == 0 {
		t.Fatalf("expected objects in hours 08 and 09, got %v", hours)
	}
	assertExactlyOnce(t, h.exported(), append(events, big))

	for _, k := range keys {
		for _, line := range readLines(t, k, h.store.Body(k)) {
			if bytes.Contains(line, []byte(`"id":"big"`)) && !bytes.Equal(line, big.Raw) {
				t.Errorf("record was not preserved verbatim: %s", line)
			}
		}
	}
}

func TestPlainJSONLinesWhenGzipIsOff(t *testing.T) {
	h := newHarness(t)
	h.s3.Gzip = false
	ev := fakes.Event("p", t0.Add(-10*time.Minute))
	h.api.Add(ev)
	h.mustRun("runner-a")
	keys := h.store.Keys("audit/data/")
	if len(keys) != 1 || !strings.HasSuffix(keys[0], ".jsonl") {
		t.Fatalf("keys = %v, want one .jsonl object", keys)
	}
	if got := h.store.Body(keys[0]); !bytes.Equal(got, append(ev.Raw, '\n')) {
		t.Fatalf("object body = %q", got)
	}
}

func TestLargeBacklogCommitsInBoundedBatches(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchEvents = 100
	events := spread("b", 1000, 2, t0.Add(-20*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	res := h.mustRun("runner-a")
	if res.Batches < 5 {
		t.Fatalf("backlog committed in %d batches, want several with MaxBatchEvents=100", res.Batches)
	}
	assertExactlyOnce(t, h.exported(), events)
}

func TestRunBudgetStopsAndNextRunContinues(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchEvents = 50
	h.cfg.MaxRunDuration = 3 * time.Minute
	events := spread("r", 600, 1, t0.Add(-20*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	h.api.Fail = func(record.Query, int) error { h.clock.Advance(20 * time.Second); return nil }

	res := h.mustRun("runner-a")
	if res.Status != StatusBudgetExhausted {
		t.Fatalf("status = %s, want %s", res.Status, StatusBudgetExhausted)
	}
	h.api.Fail = nil
	for i := 0; i < 20 && res.Status != StatusCaughtUp; i++ {
		res = h.mustRun("runner-a")
	}
	assertExactlyOnce(t, h.exported(), events)
}

func TestEndTimeCompletesABackfillStream(t *testing.T) {
	h := newHarness(t)
	h.cfg.StartTime = t0.Add(-3 * time.Hour)
	h.cfg.EndTime = t0.Add(-time.Hour)
	inside := fakes.Event("inside", t0.Add(-2*time.Hour))
	outside := fakes.Event("outside", t0.Add(-30*time.Minute))
	h.api.Add(inside, outside)
	res := h.mustRun("runner-a")
	if res.Status != StatusComplete {
		t.Fatalf("status = %s, want complete", res.Status)
	}
	h.clock.Advance(time.Hour)
	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), []record.Record{inside})
}

func TestCancelledRunNeverCommitsPastWhatItStored(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchEvents = 40
	events := spread("x", 400, 2, t0.Add(-10*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	ctx, cancel := context.WithCancel(context.Background())
	h.api.Fail = func(_ record.Query, n int) error {
		if n == 6 {
			cancel()
		}
		return nil
	}
	_, err := h.pipeline("runner-a").Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run returned %v", err)
	}
	st := h.state()
	exported := h.exported()
	for _, ev := range events {
		if ev.Time.Before(st.Watermark) && exported[ev.ID] != 1 {
			t.Fatalf("checkpoint %s passed event %s at %s which was not stored", st.Watermark, ev.ID, ev.Time)
		}
	}
	h.api.Fail = nil
	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), events)
}

func TestRunStopsAtTheEndItStartedWithWhileTimePasses(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxRunDuration = 10 * time.Minute
	events := spread("m", 30, 1, t0.Add(-90*time.Minute), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	h.api.Fail = func(record.Query, int) error { h.clock.Advance(200 * time.Millisecond); return nil }

	res := h.mustRun("runner-a")
	if res.Status != StatusCaughtUp || res.Batches != 1 {
		t.Fatalf("run = %+v, want one batch and caught-up while the clock moves", res)
	}
	if want := t0.Add(-time.Minute); !h.state().Watermark.Equal(want) {
		t.Fatalf("watermark = %s, want the run's starting end %s", h.state().Watermark, want)
	}
	assertExactlyOnce(t, h.exported(), events)
}

func TestInterruptedCheckpointWriteThatLandedStillReleasesTheLease(t *testing.T) {
	h := newHarness(t)
	events := spread("i", 20, 1, t0.Add(-60*time.Minute), t0.Add(-2*time.Minute))
	h.api.Add(events...)
	statePuts := 0
	h.store.LandThenFail = func(key string, _ int) error {
		if key == stateKey {
			statePuts++
			if statePuts == 3 {
				return context.Canceled
			}
		}
		return nil
	}
	if _, err := h.run("runner-a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("run = %v, want the injected cancellation", err)
	}
	st := h.state()
	if st.Lease != nil {
		t.Fatalf("lease %+v left behind although the landed write was this runner's", st.Lease)
	}
	if st.Pending != nil || !st.Watermark.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("landed commit was rolled back: watermark=%s pending=%v", st.Watermark, st.Pending)
	}
	h.store.LandThenFail = nil
	if res := h.mustRun("runner-b"); res.Status != StatusCaughtUp {
		t.Fatalf("next run = %+v, want caught-up without waiting for a lease", res)
	}
	assertExactlyOnce(t, h.exported(), events)
}

func TestReleaseNeverTouchesALeaseTakenOverByAnotherRunner(t *testing.T) {
	h := newHarness(t)
	h.api.Add(fakes.Event("x", t0.Add(-10*time.Minute)))
	statePuts := 0
	h.store.LandThenFail = func(key string, _ int) error {
		if key != stateKey {
			return nil
		}
		statePuts++
		if statePuts == 2 {
			stolen := h.state()
			stolen.Lease = &Lease{Owner: "runner-z", ExpiresAt: t0.Add(time.Hour)}
			body, _ := json.Marshal(stolen)
			h.store.Set(stateKey, body)
			return errors.New("injected: lease stolen")
		}
		return nil
	}
	_, _ = h.run("runner-a")
	if l := h.state().Lease; l == nil || l.Owner != "runner-z" {
		t.Fatalf("release overwrote another runner's lease: %+v", l)
	}
}

// stallStore holds the first data upload until resumed, then stores it only if its request was not aborted.
type stallStore struct {
	*fakes.Store
	once    sync.Once
	stalled chan struct{}
	resume  chan struct{}
}

func (s *stallStore) Put(ctx context.Context, key string, body []byte, opts objstore.PutOptions) (string, error) {
	if strings.Contains(key, "/data/") {
		first := false
		s.once.Do(func() { first = true })
		if first {
			close(s.stalled)
			<-s.resume
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
	}
	return s.Store.Put(ctx, key, body, opts)
}

func TestStalledUploadCannotOverwriteTheRunnerThatTookOver(t *testing.T) {
	h := newHarness(t)
	h.cfg.LeaseTTL = 300 * time.Millisecond
	events := spread("s", 10, 1, t0.Add(-50*time.Minute), t0.Add(-40*time.Minute))
	h.api.Add(events...)
	ss := &stallStore{Store: h.store, stalled: make(chan struct{}), resume: make(chan struct{})}
	cfgA := h.cfg
	cfgA.Owner = "runner-a"
	a := New(cfgA, h.api, h.sink(ss), ss, slog.New(slog.NewTextHandler(io.Discard, nil)), h.clock.Now)
	errA := make(chan error, 1)
	go func() {
		_, err := a.Run(context.Background())
		errA <- err
	}()
	<-ss.stalled

	late := fakes.Event("late", t0.Add(-45*time.Minute))
	h.api.Add(late)
	h.clock.Advance(time.Second)
	h.mustRun("runner-b")
	time.Sleep(400 * time.Millisecond)
	close(ss.resume)
	if err := <-errA; err == nil {
		t.Fatal("the stalled runner reported success after losing its lease")
	}
	assertExactlyOnce(t, h.exported(), append(events, late))
}

func TestDenseWindowAfterSparseOnesStaysWithinTheBatchLimit(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchEvents = 100
	sparse := spread("sp", 10, 1, t0.Add(-23*time.Hour), t0.Add(-3*time.Hour))
	dense := spread("dn", 3000, 3, t0.Add(-2*time.Hour), t0.Add(-90*time.Minute))
	all := append(sparse, dense...)
	h.api.Add(all...)
	h.mustRun("runner-a")
	assertExactlyOnce(t, h.exported(), all)

	perBatch := map[string]int{}
	for _, key := range h.store.Keys("audit/data/") {
		parts := strings.Split(key[strings.LastIndex(key, "/")+1:], "_")
		perBatch[parts[1]+"_"+parts[2]] += len(readLines(t, key, h.store.Body(key)))
	}
	for bounds, n := range perBatch {
		if n > h.cfg.MaxBatchEvents+h.cfg.PageSize {
			t.Errorf("batch %s held %d events, limit %d plus one page", bounds, n, h.cfg.MaxBatchEvents)
		}
	}
}

func TestWindowBoundsStayOnWholeSeconds(t *testing.T) {
	h := newHarness(t)
	h.clock = &clock{t: t0.Add(437 * time.Millisecond)}
	h.api.Add(spread("w", 500, 1, t0.Add(-5*time.Hour), t0.Add(-2*time.Minute))...)
	floor := t0.Add(437*time.Millisecond - 24*time.Hour)
	var odd []string
	h.api.Fail = func(q record.Query, _ int) error {
		if q.To.Truncate(time.Second) != q.To || (q.From != floor && q.From.Truncate(time.Second) != q.From) {
			odd = append(odd, fmtTime(q.From)+" "+fmtTime(q.To))
		}
		return nil
	}
	h.mustRun("runner-a")
	if len(odd) > 0 {
		t.Fatalf("windows off whole seconds: %v", odd)
	}
	if w := h.state().Watermark; w.Truncate(time.Second) != w {
		t.Fatalf("watermark %s is not a whole second", w)
	}
}

// loki configures the harness like the k8s audit source: oldest first, no offset pages, nanosecond timestamps.
func (h *harness) loki() {
	h.api.Ascending = true
	h.cfg.Source = record.Source{Kind: record.KindK8sAudit, Org: "acme", Name: "dev"}
	h.cfg.Pageable = false
	h.cfg.Resolution = time.Nanosecond
	h.cfg.InitialQueryWindow = 5 * time.Minute
	h.cfg.MaxQueryWindow = time.Hour
}

func (h *harness) with(sink Sink, store objstore.Store) *Pipeline {
	return New(h.cfg, h.api, sink, store, slog.New(slog.NewTextHandler(h.t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn})), h.clock.Now)
}

func assertDeliveredOnce(t *testing.T, got map[string]int, recs []record.Record) {
	t.Helper()
	want := map[string]bool{}
	for _, r := range recs {
		want[r.ID] = true
		if got[r.ID] != 1 {
			t.Errorf("record %s delivered %d times, want 1", r.ID, got[r.ID])
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("unexpected record %s delivered", id)
		}
	}
}

func TestSourceWithoutPagesAndFileStateDeliversEachRecordOnce(t *testing.T) {
	h := newHarness(t)
	h.loki()
	var recs []record.Record
	for i := 0; i < 3000; i++ {
		ts := t0.Add(-2 * time.Hour).Add(time.Duration(i/3) * 7 * time.Millisecond).Add(time.Duration(i%3) * 0)
		recs = append(recs, fakes.Event(fmt.Sprintf("k-%05d", i), ts.Add(time.Duration(i/3)*time.Nanosecond)))
	}
	h.api.Add(recs...)
	var tooLong []string
	h.api.Fail = func(q record.Query, _ int) error {
		if q.To.Sub(q.From) > time.Hour {
			tooLong = append(tooLong, fmtTime(q.From)+" "+fmtTime(q.To))
		}
		return nil
	}
	sink := &fakes.Sink{}
	p := h.with(sink, &filestore.Store{Dir: t.TempDir()})
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDeliveredOnce(t, sink.Counts(), recs)
	if len(tooLong) > 0 {
		t.Fatalf("queries longer than the source's maximum window: %v", tooLong)
	}
}

func TestSourceWithoutPagesFailsWhenOneInstantHoldsMoreThanAPage(t *testing.T) {
	h := newHarness(t)
	h.loki()
	ts := t0.Add(-30 * time.Minute)
	for i := 0; i < 60; i++ {
		h.api.Add(fakes.Event(fmt.Sprintf("same-%02d", i), ts))
	}
	sink := &fakes.Sink{}
	p := h.with(sink, h.store)
	_, err := p.Run(context.Background())
	if !errors.Is(err, ErrUnstableWindow) {
		t.Fatalf("err = %v, want ErrUnstableWindow", err)
	}
	if w := h.stateAt(p.StateKey()).Watermark; len(sink.Delivered) != 0 || !w.Equal(t0.Add(-24*time.Hour)) {
		t.Fatalf("delivered %d and moved the watermark to %s past an unreadable window", len(sink.Delivered), w)
	}
}

func TestAPipelineRunsAgainAndContinues(t *testing.T) {
	h := newHarness(t)
	sink := &fakes.Sink{}
	p := h.with(sink, h.store)
	first := spread("a", 300, 3, t0.Add(-3*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(first...)
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := spread("b", 100, 1, t0, t0.Add(55*time.Second))
	h.api.Add(second...)
	h.clock.Advance(2 * time.Minute)
	res, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Events != len(second) {
		t.Fatalf("second run delivered %d, want %d", res.Events, len(second))
	}
	assertDeliveredOnce(t, sink.Counts(), append(first, second...))
}

func TestBatchBytesBoundABatch(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchBytes = 20 << 10
	recs := spread("y", 1000, 1, t0.Add(-5*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(recs...)
	sink := &fakes.Sink{}
	res, err := h.with(sink, h.store).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	perBatch := len(recs[0].Raw)*h.cfg.PageSize + h.cfg.MaxBatchBytes
	if res.Batches < 5 || len(recs)*len(recs[0].Raw)/res.Batches > perBatch {
		t.Fatalf("%d batches for %d records, want batches of about %d bytes", res.Batches, len(recs), h.cfg.MaxBatchBytes)
	}
	assertDeliveredOnce(t, sink.Counts(), recs)
}

// stopSink cancels the run while a delivery is under way and checks that the delivery is allowed to finish.
type stopSink struct {
	fakes.Sink
	stop     context.CancelFunc
	sawAbort bool
}

func (s *stopSink) Deliver(ctx context.Context, b *record.Batch) (record.Delivered, error) {
	s.stop()
	time.Sleep(50 * time.Millisecond)
	s.sawAbort = ctx.Err() != nil
	return s.Sink.Deliver(ctx, b)
}

func TestStopDuringADeliveryLetsItFinishAndCommit(t *testing.T) {
	h := newHarness(t)
	h.cfg.DrainTimeout = 5 * time.Second
	recs := spread("d", 40, 1, t0.Add(-time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(recs...)
	ctx, cancel := context.WithCancel(context.Background())
	sink := &stopSink{stop: cancel}
	p := h.with(sink, h.store)
	_, err := p.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the stop", err)
	}
	if sink.sawAbort {
		t.Fatal("the delivery under way was aborted")
	}
	st := h.stateAt(p.StateKey())
	if st.Pending != nil || !st.Watermark.Equal(t0.Add(-time.Minute)) || st.Lease != nil {
		t.Fatalf("after a stop: watermark %s pending %v lease %v, want the delivered batch committed", st.Watermark, st.Pending, st.Lease)
	}
	assertDeliveredOnce(t, sink.Counts(), recs)
}

func TestSinkWithoutIdempotencyResendsAtMostTheFailedBatch(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchEvents = 100
	recs := spread("n", 500, 1, t0.Add(-10*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(recs...)
	sink := &fakes.Sink{Partial: 30, Fail: func(_ *record.Batch, n int) error {
		if n == 2 {
			return errors.New("injected: connection reset mid-batch")
		}
		return nil
	}}
	p := h.with(sink, h.store)
	if _, err := p.Run(context.Background()); err == nil {
		t.Fatal("run with a failed delivery succeeded")
	}
	sink.Fail = nil
	h.clock.Advance(time.Minute)
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	dups := 0
	counts := sink.Counts()
	for _, r := range recs {
		switch counts[r.ID] {
		case 1:
		case 2:
			dups++
		default:
			t.Fatalf("record %s delivered %d times", r.ID, counts[r.ID])
		}
	}
	if dups != 30 {
		t.Fatalf("%d duplicates, want exactly the 30 the failed delivery got through", dups)
	}
}

func TestAnInterruptedBatchIsRecollectedWithinTheLimitsForASinkWithoutExactReplay(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchEvents = 50
	recs := spread("p", 400, 1, t0.Add(-5*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(recs...)
	sink := &fakes.Sink{}
	p := h.with(sink, h.store)
	st := &State{
		SchemaVersion: stateSchemaVersion, Pipeline: p.ID(), Floor: t0.Add(-6 * time.Hour), Watermark: t0.Add(-6 * time.Hour),
		Recent: map[string]time.Time{}, Pending: &Pending{To: t0.Add(-time.Minute), Owner: "runner-z"},
	}
	body, _ := json.Marshal(st)
	h.store.Set(p.StateKey(), body)
	res, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Batches < 5 {
		t.Fatalf("an interrupted batch over the whole range was replayed as %d batches, want batches within the limits", res.Batches)
	}
	assertDeliveredOnce(t, sink.Counts(), recs)
}

func TestExclusiveStateTakesOverTheLeaseOfAStoppedReplica(t *testing.T) {
	h := newHarness(t)
	h.cfg.ExclusiveState = true
	recs := spread("e", 20, 1, t0.Add(-time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(recs...)
	sink := &fakes.Sink{}
	p := h.with(sink, h.store)
	st := &State{
		SchemaVersion: stateSchemaVersion, Pipeline: p.ID(), Floor: t0.Add(-2 * time.Hour), Watermark: t0.Add(-2 * time.Hour),
		Recent: map[string]time.Time{}, Lease: &Lease{Owner: "killed-replica", ExpiresAt: t0.Add(4 * time.Minute)},
	}
	body, _ := json.Marshal(st)
	h.store.Set(p.StateKey(), body)
	if res, err := p.Run(context.Background()); err != nil || res.Status != StatusCaughtUp {
		t.Fatalf("run = %+v, %v; want caught-up without waiting for the dead replica's lease", res, err)
	}
	assertDeliveredOnce(t, sink.Counts(), recs)
}

// orderedSink notes where each batch starts, in the same log as the source's queries.
type orderedSink struct {
	fakes.Sink
	log *[]string
	mu  *sync.Mutex
}

func (s *orderedSink) Deliver(ctx context.Context, b *record.Batch) (record.Delivered, error) {
	s.mu.Lock()
	*s.log = append(*s.log, "d "+fmtTime(b.From))
	s.mu.Unlock()
	return s.Sink.Deliver(ctx, b)
}

func TestOnlyTheFirstBatchOfARunRereadsTheOverlap(t *testing.T) {
	h := newHarness(t)
	h.cfg.MaxBatchEvents = 60
	h.cfg.StartTime = t0.Add(-10 * time.Hour)
	recs := spread("v", 600, 1, t0.Add(-10*time.Hour), t0.Add(-2*time.Minute))
	h.api.Add(recs...)
	var mu sync.Mutex
	var log []string
	h.api.Fail = func(q record.Query, _ int) error {
		mu.Lock()
		log = append(log, "q "+fmtTime(q.From))
		mu.Unlock()
		return nil
	}
	sink := &orderedSink{log: &log, mu: &mu}
	res, err := h.with(sink, h.store).Run(context.Background())
	if err != nil || res.Batches < 5 {
		t.Fatalf("run = %+v, %v", res, err)
	}
	// Queries before a batch's delivery belong to it; after the first batch none may start before its start.
	var pending []string
	batches := 0
	for _, e := range log {
		if strings.HasPrefix(e, "q ") {
			pending = append(pending, e[2:])
			continue
		}
		batches++
		if batches > 1 {
			for _, from := range pending {
				if from < e[2:] {
					t.Fatalf("batch %d starting %s re-read from %s", batches, e[2:], from)
				}
			}
		}
		pending = nil
	}
	assertDeliveredOnce(t, sink.Counts(), recs)
}
