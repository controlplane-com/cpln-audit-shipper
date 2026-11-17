// Package sakey gives each replica a key of the release's own service account: it adds one at startup, through the
// Control Plane API with the workload's token, and removes it when the replica stops. Keys left by replicas that
// crashed are removed by a later start in the same location.
package sakey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/httpx"
)

type Config struct {
	// Endpoint and Token are the workload's CPLN_ENDPOINT and CPLN_TOKEN.
	Endpoint string
	Token    string
	Org      string
	Name     string
	// Location keeps the keys of replicas in different locations apart; Host tells the replicas of one apart.
	Location string
	Host     string
	// StaleAfter is how old a key of this location must be before a starting replica removes it. It must outlast
	// the overlap of an old and a new replica during a rollout.
	StaleAfter time.Duration
	HTTP       *http.Client
	Logger     *slog.Logger
	Now        func() time.Time
}

// Key is a key this replica added. Value is the secret; it is only ever held in memory.
type Key struct {
	Value       string
	description string
}

type Minter struct {
	cfg  Config
	base string
	api  *httpx.Client
}

func New(cfg Config) *Minter {
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 30 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Minter{
		cfg:  cfg,
		base: strings.TrimRight(cfg.Endpoint, "/") + "/org/" + url.PathEscape(cfg.Org) + "/serviceaccount/" + url.PathEscape(cfg.Name),
		api:  &httpx.Client{Service: "Control Plane API", HTTP: cfg.HTTP, Logger: cfg.Logger, Timeout: 30 * time.Second},
	}
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

// Mint removes this location's stale keys, then adds a key for this replica.
func (m *Minter) Mint(ctx context.Context) (*Key, error) {
	keys, err := m.list(ctx)
	if err != nil {
		return nil, err
	}
	cut := m.cfg.Now().Add(-m.cfg.StaleAfter)
	if err := m.drop(ctx, m.ours(keys, func(k listedKey) bool { return k.Created.Before(cut) })); err != nil {
		return nil, err
	}
	desc := fmt.Sprintf("%s%s %s", m.prefix(), m.cfg.Now().UTC().Format(time.RFC3339), m.cfg.Host)
	if len(desc) > 250 {
		desc = desc[:250]
	}
	value, err := m.add(ctx, desc)
	var se *httpx.StatusError
	if errors.As(err, &se) && se.Status == http.StatusBadRequest && strings.Contains(se.Message, "keys") {
		// The account is full: this location's earlier keys belong to replicas that are gone or about to stop.
		if keys, err = m.list(ctx); err != nil {
			return nil, err
		}
		if err := m.drop(ctx, m.ours(keys, func(listedKey) bool { return true })); err != nil {
			return nil, err
		}
		value, err = m.add(ctx, desc)
	}
	if err != nil {
		return nil, err
	}
	return &Key{Value: value, description: desc}, nil
}

// Remove drops the key this replica added. A retried add can leave two keys with its description; both go.
func (m *Minter) Remove(ctx context.Context, k *Key) error {
	keys, err := m.list(ctx)
	if err != nil {
		return err
	}
	var names []string
	for _, l := range keys {
		if l.Description == k.description {
			names = append(names, l.Name)
		}
	}
	return m.drop(ctx, names)
}

func (m *Minter) ours(keys []listedKey, match func(listedKey) bool) []string {
	var names []string
	for _, k := range keys {
		if strings.HasPrefix(k.Description, m.prefix()) && match(k) {
			names = append(names, k.Name)
		}
	}
	return names
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

func (m *Minter) add(ctx context.Context, desc string) (string, error) {
	body, err := m.call(ctx, http.MethodPost, m.base+"/-addKey", map[string]string{"description": desc})
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
	if _, err := m.call(ctx, http.MethodPatch, m.base, map[string][]string{"$drop/keys": names}); err != nil {
		return fmt.Errorf("removing %d key(s) from service account %s: %w", len(names), m.cfg.Name, err)
	}
	if m.cfg.Logger != nil {
		m.cfg.Logger.Info("removed service account keys", "service_account", m.cfg.Name, "keys", len(names))
	}
	return nil
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
