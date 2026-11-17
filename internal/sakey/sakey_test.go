package sakey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

// fakeAPI serves one service account the way the Control Plane API does: GET lists the keys without their values,
// POST -addKey returns the new key once, and PATCH {"$drop/keys": [...]} removes keys by name.
type fakeAPI struct {
	mu    sync.Mutex
	keys  []listedKey
	seq   int
	max   int
	auths []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/org/acme/serviceaccount/r1-audit-shipper":
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "r1-audit-shipper", "keys": f.keys})
	case r.Method == http.MethodPost && r.URL.Path == "/org/acme/serviceaccount/r1-audit-shipper/-addKey":
		if len(f.keys) >= f.max {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"message":"You can only have up to %d keys for a serviceaccount"}`, f.max)
			return
		}
		var body struct{ Description string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.seq++
		f.keys = append(f.keys, listedKey{Name: fmt.Sprintf("k%d", f.seq), Created: now, Description: body.Description})
		_ = json.NewEncoder(w).Encode(map[string]any{"description": body.Description, "created": now, "key": fmt.Sprintf("secret-%d", f.seq)})
	case r.Method == http.MethodPatch && r.URL.Path == "/org/acme/serviceaccount/r1-audit-shipper":
		var body map[string][]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		drop := map[string]bool{}
		for _, n := range body["$drop/keys"] {
			drop[n] = true
		}
		var keep []listedKey
		for _, k := range f.keys {
			if !drop[k.Name] {
				keep = append(keep, k)
			}
		}
		f.keys = keep
		_, _ = w.Write([]byte(`{}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeAPI) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, k := range f.keys {
		out = append(out, k.Name)
	}
	sort.Strings(out)
	return out
}

func newMinter(t *testing.T, f *fakeAPI, location string) *Minter {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	m := New(Config{
		Endpoint: srv.URL, Token: "w.workload-token", Org: "acme", Name: "r1-audit-shipper",
		Location: "/org/acme/location/" + location, Host: "r1-audit-shipper-abc", Now: func() time.Time { return now },
	})
	m.api.Backoff = backoff.Policy{Base: time.Millisecond, Max: time.Millisecond, MaxAttempts: 2}
	return m
}

func TestMintRemovesOnlyThisLocationsStaleKeysAndAddsOne(t *testing.T) {
	f := &fakeAPI{max: 10, keys: []listedKey{
		{Name: "stale-here", Created: now.Add(-2 * time.Hour), Description: "cpln-audit-shipper aws-us-east-2 2026-11-17T10:00:00Z old"},
		{Name: "fresh-here", Created: now.Add(-5 * time.Minute), Description: "cpln-audit-shipper aws-us-east-2 2026-11-17T11:55:00Z rolling"},
		{Name: "other-location", Created: now.Add(-48 * time.Hour), Description: "cpln-audit-shipper aws-us-east-1 2026-11-15T12:00:00Z live"},
		{Name: "someone-elses", Created: now.Add(-48 * time.Hour), Description: "ci pipeline"},
	}}
	m := newMinter(t, f, "aws-us-east-2")
	k, err := m.Mint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if k.Value != "secret-1" {
		t.Fatalf("key = %q", k.Value)
	}
	if got := strings.Join(f.names(), ","); got != "fresh-here,k1,other-location,someone-elses" {
		t.Fatalf("keys after mint = %s", got)
	}
	if err := m.Remove(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.names(), ","); got != "fresh-here,other-location,someone-elses" {
		t.Fatalf("keys after remove = %s", got)
	}
	for _, a := range f.auths {
		if a != "w.workload-token" {
			t.Fatalf("authorization %q, want the workload token as is", a)
		}
	}
}

func TestAFullAccountFreesThisLocationsKeysAndRetries(t *testing.T) {
	f := &fakeAPI{max: 3, keys: []listedKey{
		{Name: "crash-1", Created: now.Add(-time.Minute), Description: "cpln-audit-shipper aws-us-east-2 a"},
		{Name: "crash-2", Created: now.Add(-2 * time.Minute), Description: "cpln-audit-shipper aws-us-east-2 b"},
		{Name: "other-location", Created: now.Add(-time.Minute), Description: "cpln-audit-shipper aws-us-east-1 c"},
	}}
	k, err := newMinter(t, f, "aws-us-east-2").Mint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.names(), ","); k.Value == "" || got != "k1,other-location" {
		t.Fatalf("keys after a full account = %s", got)
	}
}

func TestADeniedAddFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"permission denied: addKey"}`))
	}))
	defer srv.Close()
	m := New(Config{Endpoint: srv.URL, Token: "t", Org: "acme", Name: "r1-audit-shipper", Location: "l", Host: "h"})
	if _, err := m.Mint(context.Background()); err == nil || !strings.Contains(err.Error(), "addKey") {
		t.Fatalf("err = %v, want the denial", err)
	}
}
