// Package backoff computes capped exponential backoff with full jitter.
package backoff

import (
	"context"
	"math/rand/v2"
	"time"
)

type Policy struct {
	Base        time.Duration
	Max         time.Duration
	MaxAttempts int
	Rand        func() float64
}

func Default() Policy {
	return Policy{Base: 500 * time.Millisecond, Max: 30 * time.Second, MaxAttempts: 6}
}

// Delay returns the wait before retry number attempt (1-based).
func (p Policy) Delay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := p.Max
	if attempt < 31 {
		if exp := p.Base << (attempt - 1); exp > 0 && exp < p.Max {
			d = exp
		}
	}
	r := p.Rand
	if r == nil {
		r = rand.Float64
	}
	return time.Duration(r() * float64(d))
}

func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
