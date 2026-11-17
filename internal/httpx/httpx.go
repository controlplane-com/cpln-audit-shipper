// Package httpx sends HTTP requests with pacing, retries, backoff with jitter and Retry-After.
package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/controlplane-com/cpln-audit-shipper/internal/backoff"
)

const maxResponseBytes = 256 << 20

// AuthError is a 401 or 403; it is never retried.
type AuthError struct {
	Service string
	Status  int
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("%s denied the request (HTTP %d): %s", e.Service, e.Status, e.Message)
}

// StatusError is any other non-2xx response.
type StatusError struct {
	Service string
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d: %s", e.Service, e.Status, e.Message)
}

type transportError struct {
	service string
	err     error
}

func (e *transportError) Error() string { return e.service + " request failed: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

type Client struct {
	// Service names the remote end in errors and logs.
	Service     string
	HTTP        *http.Client
	Backoff     backoff.Policy
	Timeout     time.Duration
	MinInterval time.Duration
	Logger      *slog.Logger

	initOnce sync.Once
	mu       sync.Mutex
	last     time.Time
}

func (c *Client) defaults() { c.initOnce.Do(c.setDefaults) }

func (c *Client) setDefaults() {
	if c.HTTP == nil {
		c.HTTP = &http.Client{}
	}
	if c.Backoff.MaxAttempts == 0 {
		c.Backoff = backoff.Default()
	}
	if c.Timeout == 0 {
		c.Timeout = 60 * time.Second
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
}

// Do sends the request newReq builds, once per attempt, and returns the body of a 2xx response. Transport errors,
// 429 and 5xx are retried with backoff, honouring Retry-After.
func (c *Client) Do(ctx context.Context, newReq func(ctx context.Context) (*http.Request, error)) ([]byte, error) {
	c.defaults()
	for attempt := 1; ; attempt++ {
		if err := c.pace(ctx); err != nil {
			return nil, err
		}
		body, retryAfter, err := c.once(ctx, newReq)
		if err == nil {
			return body, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !retryable(err) || attempt >= c.Backoff.MaxAttempts {
			return nil, err
		}
		delay := c.Backoff.Delay(attempt)
		if retryAfter > delay {
			delay = min(retryAfter, 2*c.Backoff.Max)
		}
		c.Logger.Warn(c.Service+" request failed, retrying", "attempt", attempt, "delay_ms", delay.Milliseconds(), "error", err.Error())
		if err := backoff.Sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
}

func (c *Client) pace(ctx context.Context) error {
	if c.MinInterval <= 0 {
		return ctx.Err()
	}
	c.mu.Lock()
	wait := max(time.Until(c.last.Add(c.MinInterval)), 0)
	c.last = time.Now().Add(wait)
	c.mu.Unlock()
	return backoff.Sleep(ctx, wait)
}

func (c *Client) once(ctx context.Context, newReq func(ctx context.Context) (*http.Request, error)) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	req, err := newReq(ctx)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, &transportError{c.Service, err}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, 0, &transportError{c.Service, err}
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return body, 0, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, 0, &AuthError{Service: c.Service, Status: resp.StatusCode, Message: ErrorMessage(body)}
	default:
		return nil, RetryAfter(resp.Header.Get("Retry-After")), &StatusError{Service: c.Service, Status: resp.StatusCode, Message: ErrorMessage(body)}
	}
}

func retryable(err error) bool {
	var te *transportError
	if errors.As(err, &te) {
		return true
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status == http.StatusTooManyRequests || se.Status >= 500
	}
	return false
}

func RetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s > 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

// ErrorMessage picks the error text out of a response body, shortened for logs.
func ErrorMessage(body []byte) string {
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && (e.Error != "" || e.Message != "") {
		msg = e.Error
		if msg == "" {
			msg = e.Message
		}
	}
	if len(msg) > 300 {
		return msg[:300] + "…"
	}
	return msg
}
