package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
)

type CRTNameProvider struct {
	provider.Metadata
	BaseURL string
}

type crtNameEntry struct {
	Subdomain string `json:"subdomain"`
	Hostname  string `json:"hostname"`
	Name      string `json:"name"`
	FirstSeen string `json:"first_seen"`
}

func (e crtNameEntry) hostname() string {
	if e.Subdomain != "" {
		return e.Subdomain
	}

	if e.Hostname != "" {
		return e.Hostname
	}

	return e.Name
}

func (p *CRTNameProvider) Query(
	ctx context.Context,
	domain string,
	client *http.Client,
	_ string,
) ([]model.Result, error) {
	domain, err := normalize.Domain(domain, "")
	if err != nil {
		return nil, err
	}

	base := p.BaseURL
	if base == "" {
		base = "https://crt.name/v1/search"
	}

	endpoint, err := url.Parse(base)
	if err != nil {
		return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
	}

	params := endpoint.Query()

	params.Set("apex", domain)
	params.Set("format", "json")
	params.Set("dates", "1")

	endpoint.RawQuery = params.Encode()

	body, err := httpclient.Get(ctx, client, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_response",
			Err:    err,
		}
	}

	results := make([]model.Result, 0, len(entries))
	observedAt := time.Now().UTC()

	for _, raw := range entries {
		var hostname string
		var firstSeen *time.Time

		// Support plain JSON string entries as well as date-bearing objects.
		if err := json.Unmarshal(raw, &hostname); err != nil {
			var entry crtNameEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				return nil, &model.ProviderError{
					Reason: "invalid_response",
					Err:    err,
				}
			}

			hostname = entry.hostname()
			firstSeen = provider.ParseTimestamp(entry.FirstSeen)
		}

		hostname = strings.TrimSpace(hostname)
		if hostname == "" {
			continue
		}

		// The API expects an apex and normally returns fully qualified names.
		normalized, wildcard, err := normalize.Hostname(domain, hostname)
		if err != nil {
			continue
		}

		evidence := model.Evidence{
			Source:     p.Name(),
			ObservedAt: observedAt,
			RecordType: "hostname-index",
			Wildcard:   wildcard,
			FirstSeen:  firstSeen,
		}

		results = append(results, model.Result{
			URL:      normalized,
			Evidence: []model.Evidence{evidence},
		})
	}

	return results, nil
}
