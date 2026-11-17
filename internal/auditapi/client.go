// Package auditapi queries the Control Plane audit trail (GET /audit/org/{org}).
package auditapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
	"github.com/controlplane-com/cpln-audit-shipper/internal/record"
)

// MaxPageSize is the largest page the audit service returns; larger values are clamped server-side.
const MaxPageSize = 1000

// InvalidEventError means the API returned a record the shipper cannot identify; the window is not advanced.
type InvalidEventError struct {
	Index  int
	Reason string
}

func (e *InvalidEventError) Error() string {
	return fmt.Sprintf("audit API returned an unusable record at index %d: %s", e.Index, e.Reason)
}

type Config struct {
	Endpoint    string
	Org         string
	Context     string
	Token       string
	HTTPClient  *http.Client
	Backoff     backoff.Policy
	MinInterval time.Duration
	Timeout     time.Duration
	Logger      *slog.Logger
}

type Client struct {
	cfg  Config
	base string
	http *httpx.Client
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid audit endpoint %q", cfg.Endpoint)
	}
	base := strings.TrimRight(cfg.Endpoint, "/") + "/audit/org/" + url.PathEscape(cfg.Org)
	return &Client{cfg: cfg, base: base, http: &httpx.Client{
		Service: "audit API", HTTP: cfg.HTTPClient, Backoff: cfg.Backoff, Timeout: cfg.Timeout,
		MinInterval: cfg.MinInterval, Logger: cfg.Logger,
	}}, nil
}

// FormatTime renders a query bound at millisecond precision, the precision of stored event times.
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

func (c *Client) Query(ctx context.Context, q record.Query) ([]record.Record, error) {
	params := url.Values{}
	params.Set("contextName", c.cfg.Context)
	params.Set("fromEvent", FormatTime(q.From))
	params.Set("toEvent", FormatTime(q.To))
	params.Set("page", strconv.Itoa(q.Page))
	params.Set("pageSize", strconv.Itoa(q.Limit))
	target := c.base + "?" + params.Encode()
	body, err := c.http.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		// A raw service account key; the audit API does not take a Bearer prefix.
		req.Header.Set("Authorization", c.cfg.Token)
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	return parse(body)
}

// head is the part of an audit event the shipper reads; the record itself is kept verbatim.
type head struct {
	ID        string `json:"id"`
	EventTime string `json:"eventTime"`
	RequestID string `json:"requestId"`
	Context   struct {
		Org         string `json:"org"`
		Name        string `json:"name"`
		EventSource string `json:"eventSource"`
		Location    string `json:"location"`
	} `json:"context"`
	Subject struct {
		Name string `json:"name"`
		Data struct {
			Type string `json:"type"`
		} `json:"data"`
	} `json:"subject"`
	Resource struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Link string `json:"link"`
		Data struct {
			Links []struct {
				Rel  string `json:"rel"`
				Href string `json:"href"`
			} `json:"links"`
		} `json:"data"`
	} `json:"resource"`
	Action struct {
		Type string `json:"type"`
	} `json:"action"`
	Result struct {
		Status string `json:"status"`
	} `json:"result"`
}

func (h *head) attrs() map[string]string {
	link := h.Resource.Link
	for _, l := range h.Resource.Data.Links {
		if link == "" && l.Rel == "self" {
			link = l.Href
		}
	}
	all := map[string]string{
		"id": h.ID, "org": h.Context.Org, "context": h.Context.Name, "event_source": h.Context.EventSource,
		"location": h.Context.Location, "request_id": h.RequestID, "subject": h.Subject.Name,
		"subject_type": h.Subject.Data.Type, "resource_type": h.Resource.Type, "resource_name": h.Resource.Name,
		"resource_link": link, "action": h.Action.Type, "result": h.Result.Status,
	}
	for k, v := range all {
		if v == "" {
			delete(all, k)
		}
	}
	return all
}

func parse(body []byte) ([]record.Record, error) {
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("audit API returned an unparseable page: %w", err)
	}
	records := make([]record.Record, 0, len(page.Items))
	for i, raw := range page.Items {
		var h head
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, &InvalidEventError{Index: i, Reason: "not a JSON object"}
		}
		if h.ID == "" {
			return nil, &InvalidEventError{Index: i, Reason: "missing id"}
		}
		t, err := time.Parse(time.RFC3339Nano, h.EventTime)
		if err != nil {
			return nil, &InvalidEventError{Index: i, Reason: fmt.Sprintf("event %s has an unparseable eventTime", h.ID)}
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			return nil, &InvalidEventError{Index: i, Reason: fmt.Sprintf("event %s is not valid JSON", h.ID)}
		}
		records = append(records, record.Record{ID: h.ID, Time: t.UTC(), Raw: compact.Bytes(), Attrs: h.attrs()})
	}
	return records, nil
}
