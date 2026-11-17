// Package pipeline copies new records from a source to a sink and advances a checkpoint only after they are delivered.
package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/objstore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

// Source returns the records with q.From <= Time < q.To, at most q.Limit of them.
type Source interface {
	Query(ctx context.Context, q record.Query) ([]record.Record, error)
}

// Sink delivers a batch. A batch whose delivery failed or was interrupted is delivered again.
type Sink interface {
	Kind() string
	Deliver(ctx context.Context, b *record.Batch) (record.Delivered, error)
}

// ExactReplayer is a sink that names its output after a batch's bounds, so an interrupted batch must be replayed
// with exactly the same bounds to overwrite what it already wrote instead of duplicating it.
type ExactReplayer interface {
	ExactReplay() bool
}

type Config struct {
	Source record.Source
	Stream string
	// Prefix is where checkpoints live in the state store.
	Prefix string

	StartTime       time.Time
	InitialLookback time.Duration
	EndTime         time.Time
	SettleDelay     time.Duration
	Overlap         time.Duration

	PageSize int
	// Resolution is the precision of the source's timestamps and the smallest window it can be asked for.
	Resolution time.Duration
	// Pageable sources accept offset pages, which reads a window too dense to split any further.
	Pageable           bool
	InitialQueryWindow time.Duration
	MaxQueryWindow     time.Duration
	MaxTiePasses       int

	MaxBatchEvents int
	MaxBatchBytes  int

	LeaseTTL       time.Duration
	MaxRunDuration time.Duration
	// DrainTimeout lets a delivery that is under way finish after the run is cancelled, so a stop does not resend it.
	DrainTimeout time.Duration
	// ExclusiveState means a lock outside the checkpoint already keeps other replicas away (volume set state), so a
	// lease left by a replica that died is taken over at once instead of waiting for it to expire.
	ExclusiveState bool
	Owner          string
	// OnProgress is called after every committed batch.
	OnProgress func()
}

type Status string

const (
	StatusCaughtUp        Status = "caught-up"
	StatusBudgetExhausted Status = "budget-exhausted"
	StatusComplete        Status = "complete"
	StatusSkipped         Status = "skipped"
)

type Result struct {
	Status     Status
	Batches    int
	Events     int
	Writes     int
	Bytes      int64
	Queries    int
	Watermark  time.Time
	Lag        time.Duration
	LeaseOwner string
}

var (
	// ErrLostLease means another runner changed the checkpoint while this one held it.
	ErrLostLease = errors.New("lost the checkpoint lease to another runner")
	// ErrUnstableWindow means a window at the source's resolution held more than a page and could not be read whole.
	ErrUnstableWindow = errors.New("window could not be read consistently")
)

type Pipeline struct {
	cfg   Config
	src   Source
	sink  Sink
	store objstore.Store
	log   *slog.Logger
	now   func() time.Time

	state     *State
	etag      string
	held      bool
	lastSaved time.Time
	step      time.Duration
	queries   int
}

func New(cfg Config, src Source, sink Sink, store objstore.Store, log *slog.Logger, now func() time.Time) *Pipeline {
	if now == nil {
		now = time.Now
	}
	if cfg.MaxTiePasses < 3 {
		cfg.MaxTiePasses = 10
	}
	if cfg.Resolution <= 0 {
		cfg.Resolution = time.Millisecond
	}
	if cfg.MaxBatchBytes <= 0 {
		cfg.MaxBatchBytes = 64 << 20
	}
	cfg.InitialQueryWindow = max(cfg.InitialQueryWindow, cfg.Resolution)
	cfg.MaxQueryWindow = max(cfg.MaxQueryWindow, cfg.InitialQueryWindow)
	return &Pipeline{cfg: cfg, src: src, sink: sink, store: store, log: log, now: now, step: cfg.InitialQueryWindow}
}

type skipError struct {
	owner string
	until time.Time
}

func (e *skipError) Error() string { return "checkpoint lease held by " + e.owner }

// Run delivers everything from the checkpoint up to now minus the settle delay, then releases the lease.
// A pipeline can run again; the window size it learned carries over.
func (e *Pipeline) Run(ctx context.Context) (Result, error) {
	e.state, e.etag, e.held, e.queries = nil, "", false, 0
	var res Result
	deadline := e.now().Add(e.cfg.MaxRunDuration)
	if err := e.acquire(ctx); err != nil {
		var skip *skipError
		if errors.As(err, &skip) {
			res.Status = StatusSkipped
			res.LeaseOwner = skip.owner
			return e.finish(res), nil
		}
		return e.finish(res), err
	}
	defer e.release()

	// Fixed per run: records that settle while this run works belong to the next run.
	end := e.windowEnd()
	sinkExact := exactSink(e.sink)
	first := true
	for {
		if err := ctx.Err(); err != nil {
			return e.finish(res), err
		}
		st := e.state
		var to time.Time
		exact := st.Pending != nil && sinkExact
		if st.Pending != nil && first {
			e.log.Info("resuming an interrupted batch", "from", st.Watermark, "to", st.Pending.To, "started_by", st.Pending.Owner, "same_bounds", exact)
		}
		if exact {
			to = st.Pending.To
		} else {
			if !st.Watermark.Before(end) {
				res.Status = StatusCaughtUp
				if !e.cfg.EndTime.IsZero() && !st.Watermark.Before(e.cfg.EndTime) {
					res.Status = StatusComplete
				}
				break
			}
			if !e.now().Before(deadline) {
				res.Status = StatusBudgetExhausted
				break
			}
			to = end
		}
		// Only the first batch re-reads the overlap: later batches start where this run's previous batch ended.
		b, err := e.collect(ctx, to, exact, first || exact)
		first = false
		if err != nil {
			return e.finish(res), err
		}
		if err := e.commit(ctx, b, &res); err != nil {
			return e.finish(res), err
		}
		if e.cfg.OnProgress != nil {
			e.cfg.OnProgress()
		}
	}
	return e.finish(res), nil
}

func (e *Pipeline) finish(res Result) Result {
	res.Queries = e.queries
	if e.state != nil {
		res.Watermark = e.state.Watermark
		res.Lag = e.now().Sub(e.state.Watermark)
	}
	return res
}

func (e *Pipeline) windowEnd() time.Time {
	end := e.now().Add(-e.cfg.SettleDelay).UTC().Truncate(time.Second)
	if !e.cfg.EndTime.IsZero() && e.cfg.EndTime.Before(end) {
		end = e.cfg.EndTime
	}
	return end
}

// ID names this pipeline's checkpoint: its source, the sink kind and the stream.
func (e *Pipeline) ID() string {
	return e.cfg.Source.Partition() + "/sink=" + e.sink.Kind() + "/stream=" + e.cfg.Stream
}

func (e *Pipeline) StateKey() string {
	return path.Join(strings.Trim(e.cfg.Prefix, "/"), "state", e.ID(), "checkpoint.json")
}

func (e *Pipeline) initialState(now time.Time) *State {
	start := e.cfg.StartTime
	if start.IsZero() {
		start = now.Add(-e.cfg.InitialLookback)
	}
	start = start.UTC().Truncate(e.cfg.Resolution)
	return &State{
		SchemaVersion: stateSchemaVersion,
		Pipeline:      e.ID(),
		Floor:         start,
		Watermark:     start,
		Recent:        map[string]time.Time{},
	}
}

func (e *Pipeline) acquire(ctx context.Context) error {
	now := e.now()
	key := e.StateKey()
	body, etag, err := e.store.Get(ctx, key)
	switch {
	case errors.Is(err, objstore.ErrNotFound):
		e.state, e.etag = e.initialState(now), ""
		e.log.Info("no checkpoint found, starting a new stream", "state_key", key, "start", e.state.Floor)
	case errors.Is(err, objstore.ErrAccessDenied):
		return fmt.Errorf("reading checkpoint %s: %w (needs s3:GetObject on the state prefix, and s3:ListBucket so a missing checkpoint is reported as missing)", key, err)
	case err != nil:
		return fmt.Errorf("reading checkpoint %s: %w", key, err)
	default:
		st, err := decodeState(body, e.ID())
		if err != nil {
			return fmt.Errorf("%s: %w; refusing to reset progress (see Recovery in the README)", key, err)
		}
		e.state, e.etag = st, etag
		if !e.cfg.StartTime.IsZero() && !e.cfg.StartTime.UTC().Truncate(e.cfg.Resolution).Equal(st.Floor) {
			e.log.Info("checkpoint exists; startTime only applies to a new stream", "floor", st.Floor, "watermark", st.Watermark)
		}
	}

	if l := e.state.Lease; l != nil && l.Owner != e.cfg.Owner {
		if now.Before(l.ExpiresAt) && !e.cfg.ExclusiveState {
			return &skipError{owner: l.Owner, until: l.ExpiresAt}
		}
		e.log.Warn("taking over an expired lease", "previous_owner", l.Owner, "expired_at", l.ExpiresAt)
	}
	// A new stream's start is saved here, before anything is delivered, so a failed first run keeps it.
	next := e.state.clone()
	next.Lease = &Lease{Owner: e.cfg.Owner, AcquiredAt: now, ExpiresAt: now.Add(e.cfg.LeaseTTL)}
	if err := e.save(ctx, next); err != nil {
		if errors.Is(err, ErrLostLease) {
			return &skipError{owner: "a concurrent runner"}
		}
		return err
	}
	e.held = true
	return nil
}

func (e *Pipeline) release() {
	if !e.held {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	next := e.state.clone()
	next.Lease = nil
	err := e.save(ctx, next)
	if errors.Is(err, ErrLostLease) {
		// An interrupted write of ours may have landed; while the stored lease is still ours, release that state.
		if body, etag, gerr := e.store.Get(ctx, e.StateKey()); gerr == nil {
			cur, derr := decodeState(body, e.ID())
			if derr == nil && cur.Lease != nil && cur.Lease.Owner == e.cfg.Owner {
				e.etag = etag
				cur.Lease = nil
				err = e.save(ctx, cur)
			}
		}
	}
	if err != nil {
		e.log.Warn("could not release the lease; it expires on its own", "error", err.Error())
	}
	e.held = false
}

// save writes st conditionally on the last ETag this runner saw, so a concurrent writer can never be overwritten.
func (e *Pipeline) save(ctx context.Context, st *State) error {
	now := e.now()
	st.UpdatedAt = now
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	opts := objstore.PutOptions{ContentType: "application/json"}
	if e.etag == "" {
		opts.IfNoneMatch = true
	} else {
		opts.IfMatch = e.etag
	}
	key := e.StateKey()
	etag, err := e.store.Put(ctx, key, body, opts)
	if errors.Is(err, objstore.ErrPrecondition) {
		// A retried request whose first attempt landed fails its own precondition; accept it when the stored bytes are ours.
		cur, curTag, gerr := e.store.Get(ctx, key)
		if gerr == nil && bytes.Equal(cur, body) {
			etag, err = curTag, nil
		} else {
			e.held = false
			return fmt.Errorf("%w: %v", ErrLostLease, err)
		}
	}
	if err != nil {
		return fmt.Errorf("writing checkpoint %s: %w", key, err)
	}
	e.state, e.etag, e.lastSaved = st, etag, now
	return nil
}

func (e *Pipeline) renewIfDue(ctx context.Context) error {
	now := e.now()
	if now.Sub(e.lastSaved) < e.cfg.LeaseTTL/3 {
		return nil
	}
	next := e.state.clone()
	lease := *next.Lease
	lease.ExpiresAt = now.Add(e.cfg.LeaseTTL)
	next.Lease = &lease
	return e.save(ctx, next)
}

// hold renews the lease when due and bounds a write so it cannot land after the lease could have expired.
func (e *Pipeline) hold(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if err := e.renewIfDue(ctx); err != nil {
		return nil, nil, err
	}
	c, cancel := context.WithTimeout(ctx, e.state.Lease.ExpiresAt.Sub(e.now())-e.cfg.LeaseTTL/10)
	return c, cancel, nil
}

func (s *State) clone() *State {
	c := *s
	if s.Lease != nil {
		l := *s.Lease
		c.Lease = &l
	}
	if s.Pending != nil {
		p := *s.Pending
		c.Pending = &p
	}
	return &c
}

type batch struct {
	from    time.Time
	to      time.Time
	records []record.Record
	bytes   int
	fetched int
}

// collect reads [watermark-overlap, limit) one window at a time and keeps the records not delivered before.
// A window is complete only when it fits in one page: the audit API orders tied timestamps differently on every
// call, so offset paging could skip or repeat records. A window that fills a page is shrunk and read again.
// Without exact it stops past the watermark once a batch limit is reached, so a batch holds at most one page
// more than the limits.
func (e *Pipeline) collect(ctx context.Context, limit time.Time, exact, overlap bool) (*batch, error) {
	st := e.state
	lower := st.Watermark
	if overlap {
		lower = lower.Add(-e.cfg.Overlap)
	}
	if lower.Before(st.Floor) {
		lower = st.Floor
	}
	b := &batch{from: st.Watermark}
	seen := map[string]struct{}{}
	cursor := lower
	for cursor.Before(limit) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wEnd := e.nextBound(cursor, limit)
		recs, err := e.query(ctx, cursor, wEnd, 0)
		if err != nil {
			return nil, err
		}
		if len(recs) >= e.cfg.PageSize {
			if e.step > e.cfg.Resolution {
				e.step = e.shrink(recs)
				continue
			}
			if !e.cfg.Pageable {
				return nil, fmt.Errorf("%w: more than %d records in [%s, %s)", ErrUnstableWindow, e.cfg.PageSize, fmtTime(cursor), fmtTime(wEnd))
			}
			if recs, err = e.fetchAllPages(ctx, cursor, wEnd); err != nil {
				return nil, err
			}
		} else if len(recs) < e.cfg.PageSize/4 {
			e.step = min(e.step*2, e.cfg.MaxQueryWindow)
		}
		for _, r := range recs {
			b.fetched++
			if _, ok := st.Recent[r.ID]; ok {
				continue
			}
			if _, ok := seen[r.ID]; ok {
				continue
			}
			seen[r.ID] = struct{}{}
			b.records = append(b.records, r)
			b.bytes += len(r.Raw)
		}
		cursor = wEnd
		if err := e.renewIfDue(ctx); err != nil {
			return nil, err
		}
		if !exact && (len(b.records) >= e.cfg.MaxBatchEvents || b.bytes >= e.cfg.MaxBatchBytes) && cursor.After(st.Watermark) {
			break
		}
	}
	b.to = cursor
	sort.Slice(b.records, func(i, j int) bool {
		if !b.records[i].Time.Equal(b.records[j].Time) {
			return b.records[i].Time.Before(b.records[j].Time)
		}
		return b.records[i].ID < b.records[j].ID
	})
	return b, nil
}

// shrink picks the window after one that filled a page: half of it, or less when the page shows records denser than that.
func (e *Pipeline) shrink(page []record.Record) time.Duration {
	next := e.step / 2
	lo, hi := page[0].Time, page[0].Time
	for _, r := range page {
		if r.Time.Before(lo) {
			lo = r.Time
		}
		if r.Time.After(hi) {
			hi = r.Time
		}
	}
	if span := hi.Sub(lo) * 4 / 5; span > 0 && span < next {
		next = span
	}
	return max(e.cfg.Resolution, next.Truncate(e.cfg.Resolution))
}

// nextBound ends a window one step after cursor, cut back to a whole second when the window spans one: the audit
// service rounds bounds to seconds for queries reaching its legacy storage, so only a second holding more than a
// page of records is split below a second.
func (e *Pipeline) nextBound(cursor, limit time.Time) time.Time {
	end := cursor.Add(e.step)
	if s := end.Truncate(time.Second); s.After(cursor) {
		end = s
	}
	if end.After(limit) {
		end = limit
	}
	return end
}

// fetchAllPages pages a window that cannot be split further and repeats until two full passes find nothing new.
func (e *Pipeline) fetchAllPages(ctx context.Context, from, to time.Time) ([]record.Record, error) {
	const maxPages = 10000
	byID := map[string]record.Record{}
	quiet := 0
	for pass := 1; pass <= e.cfg.MaxTiePasses; pass++ {
		added := 0
		for page := 0; ; page++ {
			if page >= maxPages {
				return nil, fmt.Errorf("%w: more than %d pages in [%s, %s)", ErrUnstableWindow, maxPages, fmtTime(from), fmtTime(to))
			}
			items, err := e.query(ctx, from, to, page)
			if err != nil {
				return nil, err
			}
			for _, r := range items {
				if _, ok := byID[r.ID]; !ok {
					byID[r.ID] = r
					added++
				}
			}
			if len(items) < e.cfg.PageSize {
				break
			}
		}
		if pass > 1 && added == 0 {
			quiet++
		} else {
			quiet = 0
		}
		if quiet >= 2 {
			e.log.Warn("paged a window of tied timestamps", "from", from, "to", to, "records", len(byID), "passes", pass)
			out := make([]record.Record, 0, len(byID))
			for _, r := range byID {
				out = append(out, r)
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: [%s, %s) holds more than %d records with tied timestamps and kept changing over %d passes",
		ErrUnstableWindow, fmtTime(from), fmtTime(to), e.cfg.PageSize, e.cfg.MaxTiePasses)
}

func (e *Pipeline) query(ctx context.Context, from, to time.Time, page int) ([]record.Record, error) {
	e.queries++
	recs, err := e.src.Query(ctx, record.Query{From: from, To: to, Page: page, Limit: e.cfg.PageSize})
	if err != nil {
		return nil, fmt.Errorf("querying %s [%s, %s) page %d: %w", e.cfg.Source.Kind, fmtTime(from), fmtTime(to), page, err)
	}
	return recs, nil
}

func (e *Pipeline) commit(ctx context.Context, b *batch, res *Result) error {
	ctx, cancel := e.drain(ctx)
	defer cancel()
	if len(b.records) > 0 && (e.state.Pending == nil || !exactSink(e.sink)) {
		next := e.state.clone()
		next.Pending = &Pending{To: b.to, CreatedAt: e.now(), Owner: e.cfg.Owner}
		next.Lease.ExpiresAt = e.now().Add(e.cfg.LeaseTTL)
		if err := e.save(ctx, next); err != nil {
			return err
		}
	}
	var out record.Delivered
	if len(b.records) > 0 {
		var err error
		out, err = e.sink.Deliver(ctx, &record.Batch{
			Source: e.cfg.Source, Stream: e.cfg.Stream, From: b.from, To: b.to, Records: b.records, Hold: e.hold,
		})
		if err != nil {
			return err
		}
	}

	now := e.now()
	cut := b.to.Add(-e.cfg.Overlap)
	recent := make(map[string]time.Time, len(e.state.Recent))
	for id, t := range e.state.Recent {
		if !t.Before(cut) {
			recent[id] = t
		}
	}
	for _, r := range b.records {
		if !r.Time.Before(cut) {
			recent[r.ID] = r.Time
		}
	}
	next := e.state.clone()
	next.Recent = recent
	next.Watermark = b.to
	next.Pending = nil
	next.Lease.ExpiresAt = now.Add(e.cfg.LeaseTTL)
	next.Stats.DeliveredEvents += int64(len(b.records))
	next.Stats.DeliveredWrites += int64(out.Writes)
	next.Stats.DeliveredBytes += out.Bytes
	next.Stats.LastCommitAt = now
	next.Stats.LastCommitBy = e.cfg.Owner
	if err := e.save(ctx, next); err != nil {
		return err
	}

	res.Batches++
	res.Events += len(b.records)
	res.Writes += out.Writes
	res.Bytes += out.Bytes
	level := slog.LevelInfo
	if len(b.records) == 0 {
		level = slog.LevelDebug
	}
	e.log.Log(ctx, level, "batch committed",
		"from", b.from, "to", b.to, "fetched", b.fetched, "new_events", len(b.records),
		"writes", out.Writes, "bytes", out.Bytes, "watermark", b.to,
		"lag_seconds", int64(now.Sub(b.to).Seconds()))
	return nil
}

// drain keeps a commit going for DrainTimeout after ctx is cancelled, so a stop lets the delivery under way finish.
func (e *Pipeline) drain(ctx context.Context) (context.Context, context.CancelFunc) {
	if e.cfg.DrainTimeout <= 0 {
		return ctx, func() {}
	}
	c, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, func() { time.AfterFunc(e.cfg.DrainTimeout, cancel) })
	return c, func() {
		stop()
		cancel()
	}
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func exactSink(s Sink) bool {
	r, ok := s.(ExactReplayer)
	return ok && r.ExactReplay()
}
