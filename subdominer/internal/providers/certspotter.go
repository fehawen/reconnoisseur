package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
)

const certSpotterEndpoint = "https://api.certspotter.com/v1/issuances"

type CertSpotterProvider struct {
	provider.Metadata
	BaseURL string
}

type certSpotterIssuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
}

func (p *CertSpotterProvider) Query(
	ctx context.Context,
	domain string,
	client *http.Client,
	apiKey string,
) ([]model.Result, error) {
	domain, err := normalize.Domain(domain, "")
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_domain",
			Err:    err,
		}
	}

	endpoint := p.BaseURL
	if endpoint == "" {
		endpoint = certSpotterEndpoint
	}

	baseURL, err := url.Parse(endpoint)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, &model.ProviderError{
			Reason: "invalid_endpoint",
			Err:    err,
		}
	}

	headers := make(http.Header)
	if apiKey != "" {
		headers.Set("Authorization", "Bearer "+apiKey)
	}

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0)
	after := ""

	for {
		queryURL := *baseURL
		params := queryURL.Query()

		params.Set("domain", domain)
		params.Set("include_subdomains", "true")
		params.Set("match_wildcards", "true")
		params.Add("expand", "dns_names")
		params.Add("expand", "not_before")
		params.Add("expand", "not_after")

		if after != "" {
			params.Set("after", after)
		}

		queryURL.RawQuery = params.Encode()

		body, err := httpclient.Get(
			ctx,
			client,
			queryURL.String(),
			headers,
		)
		if err != nil {
			return nil, err
		}

		var issuances []certSpotterIssuance
		if err := json.Unmarshal(body, &issuances); err != nil {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    err,
			}
		}

		if len(issuances) == 0 {
			break
		}

		lastID := issuances[len(issuances)-1].ID
		if lastID == "" || lastID == after {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
			}
		}

		for _, issuance := range issuances {
			if issuance.ID == "" || issuance.DNSNames == nil {
				return nil, &model.ProviderError{
					Reason: "invalid_response",
				}
			}

			validFrom := provider.ParseTimestamp(issuance.NotBefore)
			validUntil := provider.ParseTimestamp(issuance.NotAfter)

			for _, name := range issuance.DNSNames {
				hostname, wildcard, err := normalize.Hostname(
					domain, name,
				)
				if err != nil {
					// Ignore names outside the requested domain.
					continue
				}

				evidence := model.Evidence{
					Source:     p.Name(),
					ObservedAt: observedAt,
					RecordType: "certificate",
					Wildcard:   wildcard,
					ValidFrom:  validFrom,
					ValidUntil: validUntil,
				}

				results = append(results, model.Result{
					URL:      hostname,
					Evidence: []model.Evidence{evidence},
				})
			}
		}

		after = lastID

		// Respect cancellation and the runner's provider deadline
		// before issuing the next page request.
		if err := ctx.Err(); err != nil {
			return nil, &model.ProviderError{
				Reason: "request_failed",
				Err:    err,
			}
		}
	}

	return results, nil
}
