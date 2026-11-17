package pipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const stateSchemaVersion = 1

// ErrStateInvalid means the checkpoint exists but cannot be trusted; the shipper stops instead of resetting progress.
var ErrStateInvalid = errors.New("checkpoint state is invalid")

// State is the checkpoint object. Every record with Time < Watermark that was visible when its window was read
// has been delivered; Recent holds the IDs delivered with Time in [Watermark-Overlap, Watermark).
type State struct {
	SchemaVersion int                  `json:"schemaVersion"`
	Pipeline      string               `json:"pipeline"`
	Floor         time.Time            `json:"floor"`
	Watermark     time.Time            `json:"watermark"`
	Recent        map[string]time.Time `json:"recent"`
	Pending       *Pending             `json:"pending,omitempty"`
	Lease         *Lease               `json:"lease,omitempty"`
	Stats         Stats                `json:"stats"`
	UpdatedAt     time.Time            `json:"updatedAt"`
}

// Pending records a batch whose objects may be partly uploaded; a retry rebuilds it with the same bounds and keys.
type Pending struct {
	To        time.Time `json:"to"`
	CreatedAt time.Time `json:"createdAt"`
	Owner     string    `json:"owner"`
}

type Lease struct {
	Owner      string    `json:"owner"`
	AcquiredAt time.Time `json:"acquiredAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type Stats struct {
	DeliveredEvents int64     `json:"deliveredEvents"`
	DeliveredWrites int64     `json:"deliveredWrites"`
	DeliveredBytes  int64     `json:"deliveredBytes"`
	LastCommitAt    time.Time `json:"lastCommitAt,omitempty"`
	LastCommitBy    string    `json:"lastCommitBy,omitempty"`
}

func decodeState(body []byte, pipeline string) (*State, error) {
	var st State
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %v", ErrStateInvalid, err)
	}
	if st.SchemaVersion != stateSchemaVersion {
		return nil, fmt.Errorf("%w: schemaVersion %d, this shipper reads %d", ErrStateInvalid, st.SchemaVersion, stateSchemaVersion)
	}
	if st.Pipeline != pipeline {
		return nil, fmt.Errorf("%w: it belongs to %q, not %q", ErrStateInvalid, st.Pipeline, pipeline)
	}
	if st.Floor.IsZero() || st.Watermark.IsZero() || st.Watermark.Before(st.Floor) {
		return nil, fmt.Errorf("%w: watermark %s is missing or before floor %s", ErrStateInvalid, st.Watermark, st.Floor)
	}
	if st.Pending != nil && !st.Pending.To.After(st.Watermark) {
		return nil, fmt.Errorf("%w: pending batch end %s is not after the watermark %s", ErrStateInvalid, st.Pending.To, st.Watermark)
	}
	if st.Recent == nil {
		st.Recent = map[string]time.Time{}
	}
	return &st, nil
}
