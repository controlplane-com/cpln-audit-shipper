// Package fakes provides in-memory stand-ins for the sources, the bucket and a sink, for tests.
package fakes

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/objstore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

// Audit mimics the audit service: eventTime in [from, to), ORDER BY eventTime DESC with no tiebreaker
// (ties come back in a different random order on every call), LIMIT/OFFSET paging capped at 1000.
type Audit struct {
	mu      sync.Mutex
	events  []record.Record
	rng     *rand.Rand
	Queries int
	// StableTies keeps one arbitrary tie order across calls, as an unchanged table under one plan does.
	StableTies bool
	// Ascending mimics Loki instead: oldest first, a stable order, no offset pages and no page size cap.
	Ascending bool
	// Fail, when set, is consulted before each query; a non-nil error is returned instead of results.
	Fail func(q record.Query, n int) error
}

func NewAudit(seed uint64) *Audit {
	return &Audit{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

// Add makes events visible, as if they had just been received.
func (a *Audit) Add(events ...record.Record) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, events...)
}

func (a *Audit) Query(ctx context.Context, q record.Query) ([]record.Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Queries++
	if a.Fail != nil {
		if err := a.Fail(q, a.Queries); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var match []record.Record
	for _, ev := range a.events {
		if !ev.Time.Before(q.From) && ev.Time.Before(q.To) {
			match = append(match, ev)
		}
	}
	if a.Ascending {
		if q.Page != 0 {
			return nil, fmt.Errorf("fake source: offset page %d asked of a source without pages", q.Page)
		}
		sort.SliceStable(match, func(i, j int) bool { return match[i].Time.Before(match[j].Time) })
		return append([]record.Record(nil), match[:min(q.Limit, len(match))]...), nil
	}
	rng := a.rng
	if a.StableTies {
		rng = rand.New(rand.NewPCG(1, 2))
	}
	rng.Shuffle(len(match), func(i, j int) { match[i], match[j] = match[j], match[i] })
	sort.SliceStable(match, func(i, j int) bool { return match[i].Time.After(match[j].Time) })
	size := q.Limit
	if size <= 0 || size > 1000 {
		size = 1000
	}
	start := q.Page * size
	if start >= len(match) {
		return []record.Record{}, nil
	}
	return append([]record.Record(nil), match[start:min(start+size, len(match))]...), nil
}

// Event builds a record shaped like the audit API's.
func Event(id string, t time.Time) record.Record {
	raw, _ := json.Marshal(map[string]any{
		"id":        id,
		"eventTime": t.UTC().Format(time.RFC3339Nano),
		"context":   map[string]any{"org": "acme", "name": "cpln"},
		"resource":  map[string]any{"type": "workload", "name": "w-" + id},
		"action":    map[string]any{"type": "edit"},
		"result":    map[string]any{"status": "OK"},
	})
	return record.Record{ID: id, Time: t.UTC(), Raw: raw, Attrs: map[string]string{"id": id}}
}

type object struct {
	body []byte
	etag string
	opts objstore.PutOptions
}

// Store is a bucket with S3's conditional-write semantics.
type Store struct {
	mu      sync.Mutex
	objects map[string]object
	seq     int
	Puts    int
	// FailPut, when set, is consulted before each put; a non-nil error fails it without writing.
	FailPut func(key string, n int) error
	// LandThenFail, when set, is consulted after each put is stored; a non-nil error is returned although the write landed.
	LandThenFail func(key string, n int) error
	// FailGet, when set, is consulted before each get.
	FailGet func(key string) error
}

func NewStore() *Store { return &Store{objects: map[string]object{}} }

func (s *Store) Get(_ context.Context, key string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailGet != nil {
		if err := s.FailGet(key); err != nil {
			return nil, "", err
		}
	}
	o, ok := s.objects[key]
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", objstore.ErrNotFound, key)
	}
	return append([]byte(nil), o.body...), o.etag, nil
}

func (s *Store) Put(_ context.Context, key string, body []byte, opts objstore.PutOptions) (string, error) {
	etag, n, err := s.put(key, body, opts)
	if err == nil && s.LandThenFail != nil {
		if ferr := s.LandThenFail(key, n); ferr != nil {
			return "", ferr
		}
	}
	return etag, err
}

func (s *Store) put(key string, body []byte, opts objstore.PutOptions) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Puts++
	if s.FailPut != nil {
		if err := s.FailPut(key, s.Puts); err != nil {
			return "", s.Puts, err
		}
	}
	cur, exists := s.objects[key]
	if opts.IfNoneMatch && exists {
		return "", s.Puts, fmt.Errorf("%w: %s exists", objstore.ErrPrecondition, key)
	}
	if opts.IfMatch != "" && (!exists || cur.etag != opts.IfMatch) {
		return "", s.Puts, fmt.Errorf("%w: %s etag mismatch", objstore.ErrPrecondition, key)
	}
	s.seq++
	etag := `"` + strconv.Itoa(s.seq) + `"`
	s.objects[key] = object{body: append([]byte(nil), body...), etag: etag, opts: opts}
	return etag, s.Puts, nil
}

// Set writes an object unconditionally, for seeding state in tests.
func (s *Store) Set(key string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	s.objects[key] = object{body: append([]byte(nil), body...), etag: `"` + strconv.Itoa(s.seq) + `"`}
}

// Keys lists stored keys with the given prefix, sorted.
func (s *Store) Keys(prefix string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func (s *Store) Body(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.objects[key].body...)
}

func (s *Store) Options(key string) objstore.PutOptions {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objects[key].opts
}

// Sink records what it is given, like a syslog listener or collector that keeps every message it reads.
type Sink struct {
	mu        sync.Mutex
	Delivered []record.Record
	Batches   int
	// Fail, when set, is consulted before each delivery; Partial records are kept before the error is returned.
	Fail    func(b *record.Batch, n int) error
	Partial int
}

func (s *Sink) Kind() string { return "fake" }

func (s *Sink) Deliver(ctx context.Context, b *record.Batch) (record.Delivered, error) {
	c, cancel, err := b.Hold(ctx)
	if err != nil {
		return record.Delivered{}, err
	}
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Batches++
	if s.Fail != nil {
		if err := s.Fail(b, s.Batches); err != nil {
			s.Delivered = append(s.Delivered, b.Records[:min(s.Partial, len(b.Records))]...)
			return record.Delivered{}, err
		}
	}
	if err := c.Err(); err != nil {
		return record.Delivered{}, err
	}
	s.Delivered = append(s.Delivered, b.Records...)
	return record.Delivered{Writes: 1}, nil
}

// Counts returns how many times each record ID was delivered.
func (s *Sink) Counts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, r := range s.Delivered {
		out[r.ID]++
	}
	return out
}
