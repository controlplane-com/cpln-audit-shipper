// Package record holds the types shared by sources, the pipeline and sinks.
package record

import (
	"context"
	"time"
)

// Record is one audit event: a key unique within its source, its event time, the event as one line of JSON,
// and the fields sinks expose as syslog structured data or OTLP attributes.
type Record struct {
	ID    string
	Time  time.Time
	Raw   []byte
	Attrs map[string]string
}

// Query selects records with From <= Time < To. Page is an offset page, only asked of sources that support it.
type Query struct {
	From  time.Time
	To    time.Time
	Page  int
	Limit int
}

const (
	KindCplnAudit = "cpln-audit"
	KindK8sAudit  = "k8s-audit"
)

// Source names one stream of records: an audit context or an mk8s cluster in an org.
type Source struct {
	Kind string
	Org  string
	Name string
}

// Partition is the path that keeps this source's checkpoints and objects apart from every other source's.
func (s Source) Partition() string {
	if s.Kind == KindK8sAudit {
		return "org=" + s.Org + "/source=" + s.Kind + "/cluster=" + s.Name
	}
	return "org=" + s.Org + "/source=" + s.Kind + "/context=" + s.Name
}

// Batch is a run of records in [From, To), sorted by time and ID, that a sink delivers as a unit.
type Batch struct {
	Source  Source
	Stream  string
	From    time.Time
	To      time.Time
	Records []Record
	// Hold renews the checkpoint lease when due and returns a context that ends before the lease can expire.
	// Sinks call it before each write, so a runner that stalled cannot write after another one took over.
	Hold func(ctx context.Context) (context.Context, context.CancelFunc, error)
}

// Delivered counts what a sink wrote for a batch: objects, connections or requests, and bytes.
type Delivered struct {
	Writes int
	Bytes  int64
}
