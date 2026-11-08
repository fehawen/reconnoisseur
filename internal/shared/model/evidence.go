package model

import "time"

type Evidence struct {
	Source     string    `json:"source"`
	ObservedAt time.Time `json:"observed_at"`

	SourceTime *time.Time `json:"source_time,omitempty"`

	ValidFrom  *time.Time `json:"valid_from,omitempty"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`

	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`

	RecordType string `json:"record_type,omitempty"`
	Reference  string `json:"reference,omitempty"`
	Wildcard   bool   `json:"wildcard,omitempty"`

	StatusCode  int    `json:"status_code,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}
