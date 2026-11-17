// Package lokiapi reads mk8s Kubernetes audit logs from the org's Loki (GET /logs/org/{org}/loki/api/v1/query_range).
package lokiapi

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

// MaxWindow keeps each request inside Loki's maximum query length.
const MaxWindow = time.Hour

type Config struct {
	// Endpoint is the logs service base URL. Empty looks it up as endpoints.logs in DiscoveryURL.
	Endpoint     string
	DiscoveryURL string
	Org          string
	Cluster      string
	// Pipeline is an optional LogQL pipeline appended to the stream selector, such as `| json | verb != "get"`.
	Pipeline    string
	Token       string
	HTTPClient  *http.Client
	Backoff     backoff.Policy
	MinInterval time.Duration
	Timeout     time.Duration
	Logger      *slog.Logger
}

type Client struct {
	cfg   Config
	query string
	http  *httpx.Client

	mu   sync.Mutex
	base string
}

func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" && cfg.DiscoveryURL == "" {
		return nil, fmt.Errorf("lokiapi: an endpoint or a discovery URL is required")
	}
	if p := strings.TrimSpace(cfg.Pipeline); p != "" && !strings.HasPrefix(p, "|") {
		return nil, fmt.Errorf("lokiapi: the pipeline %q must start with |", cfg.Pipeline)
	}
	c := &Client{
		cfg:   cfg,
		query: Selector(cfg.Cluster, cfg.Pipeline),
		http: &httpx.Client{
			Service: "logs API", HTTP: cfg.HTTPClient, Backoff: cfg.Backoff, Timeout: cfg.Timeout,
			MinInterval: cfg.MinInterval, Logger: cfg.Logger,
		},
	}
	if cfg.Endpoint != "" {
		c.base = strings.TrimRight(cfg.Endpoint, "/")
	}
	return c, nil
}

// Selector is the LogQL query for one cluster's audit log.
func Selector(cluster, pipeline string) string {
	q := fmt.Sprintf(`{cluster_name=%q, job="audit"}`, cluster)
	if p := strings.TrimSpace(pipeline); p != "" {
		q += " " + p
	}
	return q
}

func (c *Client) Query(ctx context.Context, q record.Query) ([]record.Record, error) {
	if q.Page != 0 {
		return nil, fmt.Errorf("lokiapi: offset pages are not supported")
	}
	base, err := c.endpoint(ctx)
	if err != nil {
		return nil, err
	}
	params := url.Values{}
	params.Set("query", c.query)
	params.Set("start", strconv.FormatInt(q.From.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(q.To.UnixNano(), 10))
	params.Set("limit", strconv.Itoa(q.Limit))
	params.Set("direction", "forward")
	target := base + "/logs/org/" + url.PathEscape(c.cfg.Org) + "/loki/api/v1/query_range?" + params.Encode()
	body, err := c.http.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", bearer(c.cfg.Token))
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	return parse(body)
}

func bearer(token string) string {
	if strings.HasPrefix(token, "Bearer ") {
		return token
	}
	return "Bearer " + token
}

func (c *Client) endpoint(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.base != "" {
		return c.base, nil
	}
	body, err := c.http.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.DiscoveryURL, nil)
	})
	if err != nil {
		return "", fmt.Errorf("looking up the logs endpoint: %w", err)
	}
	var d struct {
		Endpoints struct {
			Logs string `json:"logs"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &d); err != nil || d.Endpoints.Logs == "" {
		return "", fmt.Errorf("looking up the logs endpoint: %s has no endpoints.logs", c.cfg.DiscoveryURL)
	}
	c.base = strings.TrimRight(d.Endpoints.Logs, "/")
	return c.base, nil
}

func parse(body []byte) ([]record.Record, error) {
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][2]string       `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("logs API returned an unparseable response: %w", err)
	}
	if resp.Status != "success" {
		return nil, fmt.Errorf("logs API returned status %q", resp.Status)
	}
	if t := resp.Data.ResultType; t != "" && t != "streams" {
		return nil, fmt.Errorf("logs API returned %s, not log streams; the pipeline must not turn the query into a metric query", t)
	}
	var out []record.Record
	for _, s := range resp.Data.Result {
		for _, v := range s.Values {
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("logs API returned the timestamp %q", v[0])
			}
			out = append(out, record.Record{ID: Key(v[1]), Time: time.Unix(0, ns).UTC(), Raw: []byte(v[1]), Attrs: s.Stream})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.Before(out[j].Time)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Key identifies an audit entry: its auditID and stage, which the stages of one request share only in part.
// A line that is not an audit event falls back to a hash of the line.
func Key(line string) string {
	var ev struct {
		AuditID string `json:"auditID"`
		Stage   string `json:"stage"`
	}
	if json.Unmarshal([]byte(line), &ev) == nil && ev.AuditID != "" {
		return ev.AuditID + "/" + ev.Stage
	}
	sum := sha1.Sum([]byte(line))
	return "sha1:" + hex.EncodeToString(sum[:])
}
