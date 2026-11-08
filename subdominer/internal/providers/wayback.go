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

const (
	waybackEndpoint    = "https://web.archive.org/cdx/search/cdx"
	waybackResultLimit = 10000
)

type WaybackProvider struct {
	provider.Metadata
	BaseURL string
}

func (p *WaybackProvider) Query(
	ctx context.Context,
	domain string,
	client *http.Client,
	_ string,
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
		endpoint = waybackEndpoint
	}

	baseURL, err := url.Parse(endpoint)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, &model.ProviderError{Reason: "invalid_endpoint"}
	}

	params := baseURL.Query()

	params.Set("url", domain)
	params.Set("matchType", "domain")
	params.Set("output", "json")
	params.Set("fl", "timestamp,original")
	params.Set("collapse", "urlkey")
	params.Set("limit", strconv.Itoa(waybackResultLimit))

	baseURL.RawQuery = params.Encode()

	body, err := httpclient.Get(ctx, client, baseURL.String(), nil)
	if err != nil {
		return nil, err
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_response",
			Err:    err,
		}
	}

	if len(rows) == 0 {
		return nil, nil
	}

	// CDX JSON includes a header row before the capture records.
	header := rows[0]
	timestampIndex := -1
	originalIndex := -1

	for i, field := range header {
		switch field {
		case "timestamp":
			timestampIndex = i
		case "original":
			originalIndex = i
		}
	}

	if timestampIndex < 0 || originalIndex < 0 {
		return nil, &model.ProviderError{
			Reason: "invalid_response",
		}
	}

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0)

	for _, row := range rows[1:] {
		if timestampIndex >= len(row) || originalIndex >= len(row) {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
			}
		}

		timestamp := strings.TrimSpace(row[timestampIndex])
		original := strings.TrimSpace(row[originalIndex])
		if timestamp == "" || original == "" {
			continue
		}

		capturedAt := provider.ParseTimestamp(timestamp)

		originalURL, err := url.Parse(original)
		if err != nil || originalURL.Hostname() == "" {
			continue
		}

		hostname, wildcard, err := normalize.Hostname(
			domain, originalURL.Hostname(),
		)
		if err != nil {
			continue
		}

		reference := "https://web.archive.org/web/" +
			timestamp + "/" + original

		results = append(results, model.Result{
			URL: hostname,
			Evidence: []model.Evidence{
				{
					Source:     p.Name(),
					ObservedAt: observedAt,
					FirstSeen:  capturedAt,
					RecordType: "archived-url",
					Reference:  reference,
					Wildcard:   wildcard,
				},
			},
		})
	}

	return results, nil
}
