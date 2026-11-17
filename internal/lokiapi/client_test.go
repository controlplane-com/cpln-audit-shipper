package lokiapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

const response = `{"status":"success","data":{"resultType":"streams","result":[
 {"stream":{"cluster_name":"prod-cluster","job":"audit","verb":"get"},"values":[
   ["1763401378342918000","{\"auditID\":\"b\",\"stage\":\"ResponseComplete\",\"verb\":\"get\"}"],
   ["1763401378000000000","{\"auditID\":\"a\",\"stage\":\"ResponseComplete\",\"verb\":\"get\"}"]]},
 {"stream":{"cluster_name":"prod-cluster","job":"audit","verb":"watch"},"values":[
   ["1763401378100000000","{\"auditID\":\"w\",\"stage\":\"ResponseStarted\",\"verb\":\"watch\"}"]]}]}}`

var q = record.Query{
	From:  time.Unix(0, 1763401300000000000).UTC(),
	To:    time.Unix(0, 1763401400000000000).UTC(),
	Limit: 5000,
}

func newClient(t *testing.T, cfg Config, h http.HandlerFunc) (*Client, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	if cfg.Endpoint == "" && cfg.DiscoveryURL == "" {
		cfg.Endpoint = srv.URL
	} else if cfg.DiscoveryURL == "discover" {
		cfg.DiscoveryURL = srv.URL + "/discovery"
	}
	cfg.Org, cfg.Cluster, cfg.Token = "acme", "prod-cluster", "key"
	cfg.Backoff = backoff.Policy{Base: time.Millisecond, Max: 5 * time.Millisecond, MaxAttempts: 3}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

func TestQuerySendsTheLokiRequestAndMergesStreamsInTimeOrder(t *testing.T) {
	c, _ := newClient(t, Config{}, func(w http.ResponseWriter, r *http.Request) {
		got := map[string]string{
			"path": r.URL.Path, "auth": r.Header.Get("Authorization"), "query": r.URL.Query().Get("query"),
			"start": r.URL.Query().Get("start"), "end": r.URL.Query().Get("end"),
			"limit": r.URL.Query().Get("limit"), "direction": r.URL.Query().Get("direction"),
		}
		want := map[string]string{
			"path": "/logs/org/acme/loki/api/v1/query_range", "auth": "Bearer key",
			"query": `{cluster_name="prod-cluster", job="audit"}`, "start": "1763401300000000000",
			"end": "1763401400000000000", "limit": "5000", "direction": "forward",
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q, want %q", k, got[k], v)
			}
		}
		_, _ = w.Write([]byte(response))
	})
	recs, err := c.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range recs {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "a/ResponseComplete,w/ResponseStarted,b/ResponseComplete" {
		t.Fatalf("records = %v, want time order across streams", ids)
	}
	if recs[2].Time.UnixNano() != 1763401378342918000 || recs[1].Attrs["verb"] != "watch" {
		t.Fatalf("record = %+v", recs[2])
	}
	if string(recs[0].Raw) != `{"auditID":"a","stage":"ResponseComplete","verb":"get"}` {
		t.Fatalf("raw line changed: %s", recs[0].Raw)
	}
}

func TestPipelineIsAppendedAndMustStartWithAPipe(t *testing.T) {
	if got := Selector("prod-cluster", ` | json | verb != "get" `); got != `{cluster_name="prod-cluster", job="audit"} | json | verb != "get"` {
		t.Fatalf("selector = %s", got)
	}
	if _, err := New(Config{Endpoint: "https://logs", Pipeline: `json`}); err == nil {
		t.Fatal("a pipeline without a leading | was accepted")
	}
}

func TestEndpointComesFromDiscovery(t *testing.T) {
	var srvURL string
	c, _ := newClient(t, Config{DiscoveryURL: "discover"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/discovery" {
			if r.Header.Get("Authorization") != "" {
				t.Error("the discovery request carried the key")
			}
			_, _ = w.Write([]byte(`{"endpoints":{"logs":"` + srvURL + `"}}`))
			return
		}
		_, _ = w.Write([]byte(response))
	})
	srvURL = strings.TrimSuffix(c.cfg.DiscoveryURL, "/discovery")
	for i := 0; i < 2; i++ {
		if _, err := c.Query(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	if c.base != srvURL {
		t.Fatalf("base = %q, want %q", c.base, srvURL)
	}
}

func TestDeniedAndMetricResponsesFail(t *testing.T) {
	c, calls := newClient(t, Config{}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"permission denied"}`))
	})
	_, err := c.Query(context.Background(), q)
	var ae *httpx.AuthError
	if !errors.As(err, &ae) || *calls != 1 {
		t.Fatalf("err = %v after %d calls, want one AuthError", err, *calls)
	}

	c, _ = newClient(t, Config{}, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	})
	if _, err := c.Query(context.Background(), q); err == nil || !strings.Contains(err.Error(), "metric") {
		t.Fatalf("a metric result was accepted: %v", err)
	}
}

func TestKeyUsesAuditIDAndStageOrAHash(t *testing.T) {
	if k := Key(`{"auditID":"x","stage":"RequestReceived"}`); k != "x/RequestReceived" {
		t.Fatalf("key = %s", k)
	}
	if k := Key("not json"); !strings.HasPrefix(k, "sha1:") || k != Key("not json") {
		t.Fatalf("fallback key = %s", k)
	}
}
