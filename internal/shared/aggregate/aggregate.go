package aggregate

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
)

type key struct {
	domain string
	url    string
}

type entry struct {
	result   model.Result
	evidence map[string]model.Evidence
}

type Aggregator struct {
	entries      map[key]*entry
	normalizeURL func(string, string) (string, error)
}

func New(normalizeURL func(string, string) (string, error)) *Aggregator {
	return &Aggregator{
		entries:      make(map[key]*entry),
		normalizeURL: normalizeURL,
	}
}

func (a *Aggregator) Add(result model.Result) error {
	if a == nil {
		return fmt.Errorf("aggregator is nil")
	}

	if result.SchemaVersion != 0 && result.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", result.SchemaVersion)
	}

	domain, err := normalize.Domain(result.Domain, "")
	if err != nil {
		return err
	}

	normalizedURL, err := a.normalizeURL(result.URL, domain)
	if err != nil {
		return fmt.Errorf("normalize URL: %w", err)
	}

	k := key{domain: domain, url: normalizedURL}

	if a.entries == nil {
		a.entries = make(map[key]*entry)
	}

	item := a.entries[k]
	if item == nil {
		item = &entry{result: model.Result{SchemaVersion: model.SchemaVersion, Domain: domain, URL: normalizedURL}, evidence: make(map[string]model.Evidence)}
		a.entries[k] = item
	}

	for _, evidence := range result.Evidence {
		evidence.Source = strings.TrimSpace(evidence.Source)
		if evidence.Source == "" {
			return fmt.Errorf("evidence source is empty")
		}

		if evidence.ObservedAt.IsZero() {
			return fmt.Errorf("evidence observed_at is zero")
		}

		evidence.ObservedAt = evidence.ObservedAt.UTC()

		if evidence.SourceTime != nil {
			t := evidence.SourceTime.UTC()
			evidence.SourceTime = &t
		}

		if evidence.ValidFrom != nil {
			t := evidence.ValidFrom.UTC()
			evidence.ValidFrom = &t
		}

		if evidence.ValidUntil != nil {
			t := evidence.ValidUntil.UTC()
			evidence.ValidUntil = &t
		}

		if evidence.FirstSeen != nil {
			t := evidence.FirstSeen.UTC()
			evidence.FirstSeen = &t
		}

		if evidence.LastSeen != nil {
			t := evidence.LastSeen.UTC()
			evidence.LastSeen = &t
		}

		encoded, err := json.Marshal(evidence)
		if err != nil {
			return fmt.Errorf("encode evidence: %w", err)
		}

		item.evidence[string(encoded)] = evidence
	}

	return nil
}

func (a *Aggregator) Results() []model.Result {
	if a == nil {
		return nil
	}

	out := make([]model.Result, 0, len(a.entries))

	for _, item := range a.entries {
		result := item.result
		result.Evidence = make([]model.Evidence, 0, len(item.evidence))

		for _, evidence := range item.evidence {
			result.Evidence = append(result.Evidence, evidence)
		}

		sort.Slice(result.Evidence, func(i, j int) bool {
			left, right := result.Evidence[i], result.Evidence[j]

			if left.Source != right.Source {
				return left.Source < right.Source
			}

			if left.RecordType != right.RecordType {
				return left.RecordType < right.RecordType
			}

			if !left.ObservedAt.Equal(right.ObservedAt) {
				return left.ObservedAt.Before(right.ObservedAt)
			}

			l, _ := json.Marshal(left)
			r, _ := json.Marshal(right)

			return string(l) < string(r)
		})

		out = append(out, result)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}

		return out[i].URL < out[j].URL
	})

	return out
}

func (a *Aggregator) WriteJSONL(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("output writer is nil")
	}

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	for _, result := range a.Results() {
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("write JSONL: %w", err)
		}
	}

	return nil
}
