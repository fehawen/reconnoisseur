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

type PDChaosProvider struct {
	provider.Metadata
	BaseURL string
}

type pdChaosResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Count      int      `json:"count"`
}

func (p *PDChaosProvider) Query(
	ctx context.Context,
	domain string,
	client *http.Client,
	apiKey string,
) ([]model.Result, error) {
	domain, err := normalize.Domain(domain, "")
	if err != nil {
		return nil, err
	}

	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return nil, &model.ProviderError{Reason: "missing_api_key"}
	}

	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = "https://dns.projectdiscovery.io"
	}

	endpoint, err := url.Parse(base + "/dns/" + url.PathEscape(domain) + "/subdomains")
	if err != nil {
		return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
	}

	headers := make(http.Header)
	headers.Set("Authorization", apiKey)
	headers.Set("Connection", "close")

	body, err := httpclient.Get(ctx, client, endpoint.String(), headers)
	if err != nil {
		return nil, err
	}

	var response pdChaosResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, &model.ProviderError{Reason: "invalid_response", Err: err}
	}

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0, len(response.Subdomains))
	for _, subdomain := range response.Subdomains {
		subdomain = strings.TrimSpace(strings.TrimSuffix(subdomain, "."))
		if subdomain == "" {
			continue
		}

		// Chaos returns relative names (for example, "api" or "*.dev").
		// Preserve already-qualified names if the API returns them.
		hostname := subdomain
		if hostname != domain && !strings.HasSuffix(hostname, "."+domain) {
			hostname += "." + domain
		}

		normalized, wildcard, err := normalize.Hostname(domain, hostname)
		if err != nil {
			continue
		}

		results = append(results, model.Result{
			URL: normalized,
			Evidence: []model.Evidence{{
				Source:     p.Name(),
				ObservedAt: observedAt,
				RecordType: "subdomain-dataset",
				Wildcard:   wildcard,
			}},
		})
	}

	return results, nil
}
