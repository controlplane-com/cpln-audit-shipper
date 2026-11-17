package auditapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

const page = `{"kind":"queryresult","itemKind":"auditevent","items":[
  {"id": "a1", "eventTime": "2026-11-16T21:15:16.01Z", "receivedTime": "2026-11-16T21:15:16.041012Z",
   "context": {"org": "acme", "name": "cpln"}, "resource": {"type": "domain"}, "action": {"type": "edit"}}
]}`

func newTestClient(t *testing.T, h http.HandlerFunc) (*Client, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{
		Endpoint: srv.URL, Org: "acme", Context: "cpln", Token: "tok",
		Backoff: backoff.Policy{Base: time.Millisecond, Max: 5 * time.Millisecond, MaxAttempts: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

var q = record.Query{
	From: time.Date(2026, 11, 16, 21, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 16, 21, 30, 0, 500e6, time.UTC),
	Page: 2, Limit: 1000,
}

func TestQuerySendsTheDocumentedRequest(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got := map[string]string{
			"path": r.URL.Path, "auth": r.Header.Get("Authorization"),
			"contextName": r.URL.Query().Get("contextName"), "fromEvent": r.URL.Query().Get("fromEvent"),
			"toEvent": r.URL.Query().Get("toEvent"), "page": r.URL.Query().Get("page"), "pageSize": r.URL.Query().Get("pageSize"),
		}
		want := map[string]string{
			"path": "/audit/org/acme", "auth": "tok", "contextName": "cpln",
			"fromEvent": "2026-11-16T21:00:00.000Z", "toEvent": "2026-11-16T21:30:00.500Z", "page": "2", "pageSize": "1000",
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q, want %q", k, got[k], v)
			}
		}
		_, _ = w.Write([]byte(page))
	})
	events, err := c.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "a1" {
		t.Fatalf("events = %+v", events)
	}
	if want := time.Date(2026, 11, 16, 21, 15, 16, 10e6, time.UTC); !events[0].Time.Equal(want) {
		t.Fatalf("eventTime = %s, want %s", events[0].Time, want)
	}
	if string(events[0].Raw) != `{"id":"a1","eventTime":"2026-11-16T21:15:16.01Z","receivedTime":"2026-11-16T21:15:16.041012Z","context":{"org":"acme","name":"cpln"},"resource":{"type":"domain"},"action":{"type":"edit"}}` {
		t.Fatalf("raw record changed: %s", events[0].Raw)
	}
}

func TestQueryRetriesRateLimitsAndServerErrors(t *testing.T) {
	var n int32
	c, calls := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		switch atomic.AddInt32(&n, 1) {
		case 1:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = w.Write([]byte(page))
		}
	})
	if _, err := c.Query(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if *calls != 3 {
		t.Fatalf("calls = %d, want 3", *calls)
	}
}

func TestQueryGivesUpAfterMaxAttempts(t *testing.T) {
	c, calls := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	_, err := c.Query(context.Background(), q)
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Status != 503 {
		t.Fatalf("err = %v, want a 503 StatusError", err)
	}
	if *calls != 4 {
		t.Fatalf("calls = %d, want 4", *calls)
	}
}

func TestQueryDoesNotRetryAuthorizationOrBadRequests(t *testing.T) {
	for status, wantAuth := range map[int]bool{401: true, 403: true, 400: false} {
		c, calls := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"access denied: token invalid for org acme and audit context cpln"}`))
		})
		_, err := c.Query(context.Background(), q)
		var ae *httpx.AuthError
		if errors.As(err, &ae) != wantAuth || err == nil {
			t.Errorf("status %d: err = %v", status, err)
		}
		if *calls != 1 {
			t.Errorf("status %d: calls = %d, want 1", status, *calls)
		}
	}
}

func TestQueryRejectsRecordsWithoutIdentity(t *testing.T) {
	for name, body := range map[string]string{
		"missing id":    `{"items":[{"eventTime":"2026-11-16T21:15:16.01Z"}]}`,
		"bad time":      `{"items":[{"id":"x","eventTime":"yesterday"}]}`,
		"not an object": `{"items":[42]}`,
	} {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })
		_, err := c.Query(context.Background(), q)
		var ie *InvalidEventError
		if !errors.As(err, &ie) {
			t.Errorf("%s: err = %v, want InvalidEventError", name, err)
		}
	}
}

func TestRecordsCarryTheFieldsSinksExpose(t *testing.T) {
	body := []byte(`{"items":[{"id":"e1","eventTime":"2026-11-16T19:39:15.029Z","requestId":"r1",
	  "context":{"org":"acme","name":"cpln","eventSource":"api.cpln.io","location":"gcp-us-east4"},
	  "subject":{"name":"/org/acme/serviceaccount/ci","data":{"type":"serviceaccount"}},
	  "resource":{"type":"domain","name":"x.example.com","data":{"links":[{"rel":"org","href":"/org/acme"},{"rel":"self","href":"/org/acme/domain/x.example.com"}]}},
	  "action":{"type":"edit"},"result":{"status":"OK"}}]}`)
	recs, err := parse(body)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"id": "e1", "org": "acme", "context": "cpln", "event_source": "api.cpln.io", "location": "gcp-us-east4",
		"request_id": "r1", "subject": "/org/acme/serviceaccount/ci", "subject_type": "serviceaccount",
		"resource_type": "domain", "resource_name": "x.example.com", "resource_link": "/org/acme/domain/x.example.com",
		"action": "edit", "result": "OK",
	}
	got := recs[0].Attrs
	if len(got) != len(want) {
		t.Errorf("attrs = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attr %s = %q, want %q", k, got[k], v)
		}
	}
}
