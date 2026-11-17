// Package s3sink writes batches to a bucket as JSON Lines, one object per UTC hour, split by count and size.
package s3sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"log/slog"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/objstore"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

type Config struct {
	Store           objstore.Store
	Prefix          string
	Gzip            bool
	MaxObjectEvents int
	MaxObjectBytes  int
	Logger          *slog.Logger
}

type Sink struct{ cfg Config }

func New(cfg Config) *Sink { return &Sink{cfg: cfg} }

func (s *Sink) Kind() string { return "s3" }

// ExactReplay is true: objects are named after the batch bounds, so a replay with the same bounds overwrites them.
func (s *Sink) ExactReplay() bool { return true }

// Key is the object holding part `part` of hour `hour` of the batch [from, to). It depends only on the batch
// bounds and the record order, so a replayed batch overwrites the same objects.
func (s *Sink) Key(src record.Source, stream string, hour, from, to time.Time, part int) string {
	ext := ".jsonl"
	if s.cfg.Gzip {
		ext += ".gz"
	}
	h := hour.UTC()
	return path.Join(strings.Trim(s.cfg.Prefix, "/"), "data", src.Partition(),
		fmt.Sprintf("year=%04d", h.Year()), fmt.Sprintf("month=%02d", int(h.Month())),
		fmt.Sprintf("day=%02d", h.Day()), fmt.Sprintf("hour=%02d", h.Hour()),
		fmt.Sprintf("%s_%s_%s_%04d%s", stream, CompactTime(from), CompactTime(to), part, ext))
}

func CompactTime(t time.Time) string {
	return strings.Replace(t.UTC().Format("20060102T150405.000Z"), ".", "", 1)
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (s *Sink) Deliver(ctx context.Context, b *record.Batch) (record.Delivered, error) {
	var (
		out         record.Delivered
		buf         bytes.Buffer
		hour        time.Time
		part, n     int
		first, last time.Time
	)
	flush := func() error {
		if n == 0 {
			return nil
		}
		key := s.Key(b.Source, b.Stream, hour, b.From, b.To, part)
		body, contentType, err := s.encode(buf.Bytes())
		if err != nil {
			return err
		}
		putCtx, cancel, err := b.Hold(ctx)
		if err != nil {
			return err
		}
		defer cancel()
		_, err = s.cfg.Store.Put(putCtx, key, body, objstore.PutOptions{
			ContentType: contentType,
			Metadata: map[string]string{
				"event-count":      strconv.Itoa(n),
				"first-event-time": formatTime(first),
				"last-event-time":  formatTime(last),
				"stream":           b.Stream,
				"batch-from":       formatTime(b.From),
				"batch-to":         formatTime(b.To),
			},
		})
		if err != nil {
			return fmt.Errorf("uploading %s: %w", key, err)
		}
		out.Writes++
		out.Bytes += int64(len(body))
		if s.cfg.Logger != nil {
			s.cfg.Logger.Debug("object uploaded", "key", key, "events", n, "bytes", len(body))
		}
		part++
		buf.Reset()
		n = 0
		return nil
	}
	for _, r := range b.Records {
		h := r.Time.UTC().Truncate(time.Hour)
		if n > 0 && !h.Equal(hour) {
			if err := flush(); err != nil {
				return out, err
			}
		}
		if !h.Equal(hour) {
			hour, part = h, 0
		}
		if n > 0 && (n >= s.cfg.MaxObjectEvents || buf.Len()+len(r.Raw)+1 > s.cfg.MaxObjectBytes) {
			if err := flush(); err != nil {
				return out, err
			}
		}
		if n == 0 {
			first = r.Time
		}
		buf.Write(r.Raw)
		buf.WriteByte('\n')
		n++
		last = r.Time
	}
	if err := flush(); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Sink) encode(lines []byte) ([]byte, string, error) {
	if !s.cfg.Gzip {
		return bytes.Clone(lines), "application/x-ndjson", nil
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(lines); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return out.Bytes(), "application/gzip", nil
}
