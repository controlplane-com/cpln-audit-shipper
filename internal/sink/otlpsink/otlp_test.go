package otlpsink

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

type request struct {
	path, auth, encoding string
	body                 map[string]any
}

func collector(t *testing.T, answer func(n int) int) (*httptest.Server, func() []request) {
	t.Helper()
	var mu sync.Mutex
	var got []request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rd io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Errorf("bad gzip: %v", err)
				return
			}
			rd = zr
		}
		var body map[string]any
		if err := json.NewDecoder(rd).Decode(&body); err != nil {
			t.Errorf("bad JSON: %v", err)
		}
		mu.Lock()
		got = append(got, request{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Encoding"), body})
		n := len(got)
		mu.Unlock()
		status := answer(n)
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "0")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []request {
		mu.Lock()
		defer mu.Unlock()
		return append([]request(nil), got...)
	}
}

func newSink(t *testing.T, endpoint string, cfg Config) *Sink {
	t.Helper()
	cfg.Endpoint = endpoint
	cfg.Backoff = backoff.Policy{Base: time.Millisecond, Max: 5 * time.Millisecond, MaxAttempts: 3}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(0, 42) }
	return s
}

func batch(src record.Source, n int) *record.Batch {
	b := &record.Batch{Source: src, Hold: func(ctx context.Context) (context.Context, context.CancelFunc, error) {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		return c, cancel, nil
	}}
	for i := 0; i < n; i++ {
		b.Records = append(b.Records, record.Record{
			ID: "id" + string(rune('a'+i)), Time: time.Unix(0, 1763401378342918123+int64(i)).UTC(),
			Raw: []byte(`{"auditID":"x"}`), Attrs: map[string]string{"verb": "get", "cluster_name": "prod-cluster"},
		})
	}
	return b
}

var k8s = record.Source{Kind: record.KindK8sAudit, Org: "acme", Name: "prod-cluster"}

func TestPostsOTLPJSONLogsWithResourceAndRecordAttributes(t *testing.T) {
	srv, got := collector(t, func(int) int { return http.StatusOK })
	s := newSink(t, srv.URL, Config{Headers: map[string]string{"Authorization": "Api-Token t"}, Version: "1.0.0", Gzip: true})
	out, err := s.Deliver(context.Background(), batch(k8s, 2))
	if err != nil {
		t.Fatal(err)
	}
	reqs := got()
	if len(reqs) != 1 || out.Writes != 1 {
		t.Fatalf("%d requests, %d writes", len(reqs), out.Writes)
	}
	r := reqs[0]
	if r.path != "/v1/logs" || r.auth != "Api-Token t" || r.encoding != "gzip" {
		t.Fatalf("request %s auth %q encoding %q", r.path, r.auth, r.encoding)
	}
	rl := r.body["resourceLogs"].([]any)[0].(map[string]any)
	res := attrs(rl["resource"].(map[string]any)["attributes"])
	if res["service.name"] != "cpln-audit-shipper" || res["cpln.org"] != "acme" || res["k8s.cluster.name"] != "prod-cluster" {
		t.Fatalf("resource attributes = %v", res)
	}
	logs := rl["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)
	first := logs[0].(map[string]any)
	if first["timeUnixNano"] != "1763401378342918123" || first["observedTimeUnixNano"] != "42" {
		t.Fatalf("times = %v %v", first["timeUnixNano"], first["observedTimeUnixNano"])
	}
	if first["body"].(map[string]any)["stringValue"] != `{"auditID":"x"}` {
		t.Fatalf("body = %v", first["body"])
	}
	if a := attrs(first["attributes"]); a["audit.id"] != "ida" || a["verb"] != "get" {
		t.Fatalf("record attributes = %v", a)
	}
}

func attrs(v any) map[string]string {
	out := map[string]string{}
	for _, kv := range v.([]any) {
		m := kv.(map[string]any)
		out[m["key"].(string)] = m["value"].(map[string]any)["stringValue"].(string)
	}
	return out
}

func TestSplitsABatchIntoRequests(t *testing.T) {
	srv, got := collector(t, func(int) int { return http.StatusOK })
	s := newSink(t, srv.URL+"/otlp/v1/logs", Config{MaxRequestRecords: 3})
	out, err := s.Deliver(context.Background(), batch(k8s, 7))
	if err != nil {
		t.Fatal(err)
	}
	reqs := got()
	if len(reqs) != 3 || out.Writes != 3 || reqs[0].path != "/otlp/v1/logs" {
		t.Fatalf("%d requests to %s", len(reqs), reqs[0].path)
	}
}

func TestRetriesThrottlingAndFailsOnRejection(t *testing.T) {
	srv, got := collector(t, func(n int) int {
		if n == 1 {
			return http.StatusTooManyRequests
		}
		return http.StatusOK
	})
	if _, err := newSink(t, srv.URL, Config{}).Deliver(context.Background(), batch(k8s, 1)); err != nil || len(got()) != 2 {
		t.Fatalf("err %v after %d requests, want success on the retry", err, len(got()))
	}

	srv, got = collector(t, func(int) int { return http.StatusBadRequest })
	_, err := newSink(t, srv.URL, Config{}).Deliver(context.Background(), batch(k8s, 1))
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Status != 400 || len(got()) != 1 {
		t.Fatalf("err %v after %d requests, want one 400 without retries", err, len(got()))
	}
}

func TestRejectsAnEndpointThatIsNotAURL(t *testing.T) {
	if _, err := New(Config{Endpoint: "collector:4318"}); err == nil {
		t.Fatal("accepted an endpoint without a scheme")
	}
}
