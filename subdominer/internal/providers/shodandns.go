package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
)

type ShodanDNSProvider struct {
	provider.Metadata
	BaseURL string
}

type shodanDNSResponse struct {
	Data []shodanDNSRecord `json:"data"`
	More bool              `json:"more"`
}

type shodanDNSRecord struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	LastSeen  string `json:"last_seen"`
}

func (p *ShodanDNSProvider) Query(
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
		base = "https://api.shodan.io"
	}

	endpoint, err := url.Parse(
		base + "/dns/domain/" + url.PathEscape(domain),
	)
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_endpoint",
			Err:    err,
		}
	}

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0)
	page := 1

	for {
		params := endpoint.Query()

		params.Set("key", apiKey)
		params.Set("page", strconv.Itoa(page))

		endpoint.RawQuery = params.Encode()

		body, err := httpclient.Get(ctx, client, endpoint.String(), nil)
		if err != nil {
			return nil, err
		}

		var response shodanDNSResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    err,
			}
		}

		for _, record := range response.Data {
			subdomain := strings.TrimSpace(record.Subdomain)

			hostname := domain
			if subdomain != "" {
				subdomain = strings.TrimSuffix(subdomain, ".")

				// Shodan normally returns relative subdomain names.
				// Also tolerate fully qualified names.
				if subdomain == domain ||
					strings.HasSuffix(subdomain, "."+domain) {
					hostname = subdomain
				} else {
					hostname = subdomain + "." + domain
				}
			}

			normalized, wildcard, err := normalize.Hostname(domain, hostname)
			if err != nil {
				// Ignore names outside the requested domain.
				continue
			}

			evidence := model.Evidence{
				Source:     p.Name(),
				ObservedAt: observedAt,
				RecordType: strings.ToUpper(strings.TrimSpace(record.Type)),
				Wildcard:   wildcard,
				LastSeen:   provider.ParseTimestamp(record.LastSeen),
			}

			results = append(results, model.Result{
				URL:      normalized,
				Evidence: []model.Evidence{evidence},
			})
		}

		if !response.More {
			break
		}

		page++
	}

	return results, nil
}
