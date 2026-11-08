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

const otxPassiveDNSEndpoint = "https://otx.alienvault.com/api/v1/indicators/domain/"

type OTXProvider struct {
	provider.Metadata
	BaseURL string
}

func (p *OTXProvider) Query(
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
		endpoint = otxPassiveDNSEndpoint
	}

	endpointURL, err := url.Parse(endpoint + url.PathEscape(domain) + "/passive_dns")
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_endpoint",
			Err:    err,
		}
	}

	headers := make(http.Header)
	if apiKey != "" {
		headers.Set("X-OTX-API-KEY", apiKey)
	}

	body, err := httpclient.Get(
		ctx,
		client,
		endpointURL.String(),
		headers,
	)
	if err != nil {
		return nil, err
	}

	var response struct {
		PassiveDNS []struct {
			Hostname   string `json:"hostname"`
			RecordType string `json:"record_type"`
			First      string `json:"first"`
			Last       string `json:"last"`
		} `json:"passive_dns"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_json",
			Err:    err,
		}
	}

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0, len(response.PassiveDNS))

	for _, record := range response.PassiveDNS {
		hostname, wildcard, err := normalize.Hostname(domain, record.Hostname)
		if err != nil {
			continue
		}

		firstSeen := provider.ParseTimestamp(record.First)
		lastSeen := provider.ParseTimestamp(record.Last)

		results = append(results, model.Result{
			URL: hostname,
			Evidence: []model.Evidence{
				{
					Source:     p.Name(),
					ObservedAt: observedAt,
					FirstSeen:  firstSeen,
					LastSeen:   lastSeen,
					RecordType: strings.TrimSpace(record.RecordType),
					Reference:  endpointURL.String(),
					Wildcard:   wildcard,
				},
			},
		})
	}

	return results, nil
}
