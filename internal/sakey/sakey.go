// Package sakey gives each replica a key of the release's own service account: it adds one at startup, through the
// Control Plane API with the workload's token, and removes it when the replica stops. A location runs one replica,
// so a starting replica first removes the keys its location's earlier replicas left.
package sakey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
)

type Config struct {
	// Endpoint and Token are the workload's CPLN_ENDPOINT and CPLN_TOKEN.
	Endpoint string
	Token    string
	Org      string
	Name     string
	// Location keeps the keys of replicas in different locations apart; Host tells one replica's key from the next.
	Location string
	Host     string
	HTTP     *http.Client
	Logger   *slog.Logger
	Now      func() time.Time
}

// Key is the key this replica added. It is only ever held in memory.
type Key struct {
	Value string
}

type Minter struct {
	cfg  Config
	base string
	desc string
	api  *httpx.Client
	// conflictTries bounds the retries of a write the API rejected because the account changed meanwhile.
	conflictTries int
	conflictWait  func() time.Duration
}

func New(cfg Config) *Minter {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	m := &Minter{
		cfg:           cfg,
		base:          strings.TrimRight(cfg.Endpoint, "/") + "/org/" + url.PathEscape(cfg.Org) + "/serviceaccount/" + url.PathEscape(cfg.Name),
		api:           &httpx.Client{Service: "Control Plane API", HTTP: cfg.HTTP, Logger: cfg.Logger, Timeout: 30 * time.Second},
		conflictTries: 5,
		conflictWait:  func() time.Duration { return time.Second + rand.N(2*time.Second) },
	}
	// One description per process, so every key this process adds, including retried ones, is found again.
	m.desc = fmt.Sprintf("%s%s %s", m.prefix(), cfg.Now().UTC().Format(time.RFC3339), cfg.Host)
	if len(m.desc) > 250 {
		m.desc = m.desc[:250]
	}
	return m
}

// prefix starts the description of every key this location's replicas add.
func (m *Minter) prefix() string {
	return "cpln-audit-shipper " + path.Base(m.cfg.Location) + " "
}

type listedKey struct {
	Name        string    `json:"name"`
	Created     time.Time `json:"created"`
	Description string    `json:"description"`
}

// Mint removes the keys this location's earlier replicas left, which are gone or stopping, then adds this replica's.
func (m *Minter) Mint(ctx context.Context) (*Key, error) {
	keys, err := m.list(ctx)
	if err != nil {
		return nil, err
	}
	var stale []string
	for _, k := range keys {
		if strings.HasPrefix(k.Description, m.prefix()) {
			stale = append(stale, k.Name)
		}
	}
	if err := m.drop(ctx, stale); err != nil {
		return nil, err
	}
	value, err := m.add(ctx)
	if err != nil {
		return nil, err
	}
	return &Key{Value: value}, nil
}

// Present reports whether this replica's key still exists.
func (m *Minter) Present(ctx context.Context) (bool, error) {
	keys, err := m.list(ctx)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if k.Description == m.desc {
			return true, nil
		}
	}
	return false, nil
}

// Remove drops every key this replica added.
func (m *Minter) Remove(ctx context.Context) error {
	keys, err := m.list(ctx)
	if err != nil {
		return err
	}
	var names []string
	for _, k := range keys {
		if k.Description == m.desc {
			names = append(names, k.Name)
		}
	}
	return m.drop(ctx, names)
}

func (m *Minter) list(ctx context.Context) ([]listedKey, error) {
	body, err := m.call(ctx, http.MethodGet, m.base, nil)
	if err != nil {
		return nil, fmt.Errorf("reading service account %s: %w", m.cfg.Name, err)
	}
	var sa struct {
		Keys []listedKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &sa); err != nil {
		return nil, fmt.Errorf("reading service account %s: %w", m.cfg.Name, err)
	}
	return sa.Keys, nil
}

func (m *Minter) add(ctx context.Context) (string, error) {
	var body []byte
	err := m.retryConflicts(ctx, func() error {
		var err error
		body, err = m.call(ctx, http.MethodPost, m.base+"/-addKey", map[string]string{"description": m.desc})
		return err
	})
	if err != nil {
		return "", fmt.Errorf("adding a key to service account %s: %w", m.cfg.Name, err)
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Key == "" {
		return "", fmt.Errorf("adding a key to service account %s: the response holds no key", m.cfg.Name)
	}
	return out.Key, nil
}

func (m *Minter) drop(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	err := m.retryConflicts(ctx, func() error {
		_, err := m.call(ctx, http.MethodPatch, m.base, map[string][]string{"$drop/keys": names})
		return err
	})
	if err != nil {
		return fmt.Errorf("removing %d key(s) from service account %s: %w", len(names), m.cfg.Name, err)
	}
	if m.cfg.Logger != nil {
		m.cfg.Logger.Info("removed service account keys", "service_account", m.cfg.Name, "keys", len(names))
	}
	return nil
}

// retryConflicts retries a write the API rejected because the account changed meanwhile (409), or reported as full
// while another replica was writing it (400; its retry can count stale keys).
func (m *Minter) retryConflicts(ctx context.Context, write func() error) error {
	for try := 1; ; try++ {
		err := write()
		var se *httpx.StatusError
		retry := errors.As(err, &se) && (se.Status == http.StatusConflict ||
			se.Status == http.StatusBadRequest && strings.Contains(se.Message, "keys"))
		if !retry || try >= m.conflictTries {
			return err
		}
		if err := backoff.Sleep(ctx, m.conflictWait()); err != nil {
			return err
		}
	}
}

func (m *Minter) call(ctx context.Context, method, target string, payload any) ([]byte, error) {
	var data []byte
	if payload != nil {
		var err error
		if data, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}
	return m.api.Do(ctx, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", m.cfg.Token)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return req, nil
	})
}
