// Package otlpsink sends batches as OTLP/HTTP logs with JSON encoding.
package otlpsink

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

type Config struct {
	// Endpoint is the collector's base URL; /v1/logs is appended unless the path already ends with it.
	Endpoint string
	Headers  map[string]string
	// CAFile is a PEM bundle that replaces the system CAs.
	CAFile            string
	Gzip              bool
	Timeout           time.Duration
	MaxRequestRecords int
	MaxRequestBytes   int
	Version           string
	Backoff           backoff.Policy
	HTTPClient        *http.Client
	Logger            *slog.Logger
}

type Sink struct {
	cfg  Config
	url  string
	http *httpx.Client
	now  func() time.Time
}

func New(cfg Config) (*Sink, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("OTLP endpoint %q must be an http(s) URL", cfg.Endpoint)
	}
	if !strings.HasSuffix(u.Path, "/v1/logs") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/logs"
	}
	if cfg.MaxRequestRecords <= 0 {
		cfg.MaxRequestRecords = 1000
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 4 << 20
	}
	if cfg.HTTPClient == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading the OTLP CA bundle: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("the OTLP CA bundle %s holds no PEM certificates", cfg.CAFile)
			}
			tr.TLSClientConfig.RootCAs = pool
		}
		cfg.HTTPClient = &http.Client{Transport: tr}
	}
	return &Sink{cfg: cfg, url: u.String(), now: time.Now, http: &httpx.Client{
		Service: "OTLP endpoint", HTTP: cfg.HTTPClient, Backoff: cfg.Backoff, Timeout: cfg.Timeout, Logger: cfg.Logger,
	}}, nil
}

func (s *Sink) Kind() string { return "otlp" }

// Deliver posts the batch in requests of at most MaxRequestRecords records and about MaxRequestBytes. A 2xx is an
// acknowledgement; 429 and 5xx are retried; any other answer fails the batch, which is then delivered again.
func (s *Sink) Deliver(ctx context.Context, b *record.Batch) (record.Delivered, error) {
	var out record.Delivered
	resource := s.resource(b.Source)
	for start := 0; start < len(b.Records); {
		end, size := start, 0
		for end < len(b.Records) && end-start < s.cfg.MaxRequestRecords && (end == start || size+len(b.Records[end].Raw) <= s.cfg.MaxRequestBytes) {
			size += len(b.Records[end].Raw)
			end++
		}
		body, err := s.encode(resource, b.Records[start:end])
		if err != nil {
			return out, err
		}
		if err := s.post(ctx, b, body); err != nil {
			return out, fmt.Errorf("posting records %d to %d of the batch to %s: %w", start, end, s.url, err)
		}
		out.Writes++
		out.Bytes += int64(len(body))
		start = end
	}
	return out, nil
}

func (s *Sink) post(ctx context.Context, b *record.Batch, body []byte) error {
	ctx, cancel, err := b.Hold(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	resp, err := s.http.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		if s.cfg.Gzip {
			req.Header.Set("Content-Encoding", "gzip")
		}
		for k, v := range s.cfg.Headers {
			req.Header.Set(k, v)
		}
		return req, nil
	})
	if err != nil {
		return err
	}
	var ack struct {
		PartialSuccess struct {
			RejectedLogRecords json.Number `json:"rejectedLogRecords"`
			ErrorMessage       string      `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if json.Unmarshal(resp, &ack) == nil && ack.PartialSuccess.RejectedLogRecords != "" && ack.PartialSuccess.RejectedLogRecords != "0" && s.cfg.Logger != nil {
		s.cfg.Logger.Warn("OTLP endpoint rejected some records", "rejected", ack.PartialSuccess.RejectedLogRecords.String(), "message", ack.PartialSuccess.ErrorMessage)
	}
	return nil
}

type anyValue struct {
	StringValue string `json:"stringValue"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

type logRecord struct {
	TimeUnixNano         string     `json:"timeUnixNano"`
	ObservedTimeUnixNano string     `json:"observedTimeUnixNano"`
	SeverityNumber       int        `json:"severityNumber"`
	SeverityText         string     `json:"severityText"`
	Body                 anyValue   `json:"body"`
	Attributes           []keyValue `json:"attributes"`
}

func (s *Sink) resource(src record.Source) []keyValue {
	attrs := []keyValue{
		{"service.name", anyValue{"cpln-audit-shipper"}},
		{"cpln.org", anyValue{src.Org}},
		{"cpln.audit.source", anyValue{src.Kind}},
	}
	if src.Kind == record.KindK8sAudit {
		return append(attrs, keyValue{"k8s.cluster.name", anyValue{src.Name}})
	}
	return append(attrs, keyValue{"cpln.audit.context", anyValue{src.Name}})
}

func (s *Sink) encode(resource []keyValue, recs []record.Record) ([]byte, error) {
	observed := strconv.FormatInt(s.now().UnixNano(), 10)
	logs := make([]logRecord, len(recs))
	for i, r := range recs {
		attrs := []keyValue{{"audit.id", anyValue{r.ID}}}
		keys := make([]string, 0, len(r.Attrs))
		for k := range r.Attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			attrs = append(attrs, keyValue{k, anyValue{r.Attrs[k]}})
		}
		logs[i] = logRecord{
			TimeUnixNano: strconv.FormatInt(r.Time.UnixNano(), 10), ObservedTimeUnixNano: observed,
			SeverityNumber: 9, SeverityText: "INFO", Body: anyValue{string(r.Raw)}, Attributes: attrs,
		}
	}
	payload := map[string]any{"resourceLogs": []any{map[string]any{
		"resource": map[string]any{"attributes": resource},
		"scopeLogs": []any{map[string]any{
			"scope":      map[string]any{"name": "cpln-audit-shipper", "version": s.cfg.Version},
			"logRecords": logs,
		}},
	}}}
	body, err := json.Marshal(payload)
	if err != nil || !s.cfg.Gzip {
		return body, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
