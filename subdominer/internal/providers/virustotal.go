package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
)

const (
	virusTotalPageSize = 40
	virusTotalMaxPages = 100
)

type VirusTotalProvider struct {
	provider.Metadata
	BaseURL string
}

type virusTotalResponse struct {
	Data  []virusTotalDomain `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
}

type virusTotalDomain struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		FirstSeenDate int64 `json:"first_seen_date"`
	} `json:"attributes"`
}

func (p *VirusTotalProvider) Query(
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
		base = "https://www.virustotal.com"
	}

	endpoint, err := url.Parse(
		base + "/api/v3/domains/" + url.PathEscape(domain) + "/subdomains",
	)
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_endpoint",
			Err:    err,
		}
	}

	headers := make(http.Header)
	headers.Set("x-apikey", apiKey)

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0)
	seen := make(map[string]bool)
	cursor := ""

	for page := 1; page <= virusTotalMaxPages; page++ {
		params := url.Values{}

		params.Set("limit", fmt.Sprint(virusTotalPageSize))

		if cursor != "" {
			params.Set("cursor", cursor)
		}

		requestURL := *endpoint
		requestURL.RawQuery = params.Encode()

		body, err := httpclient.Get(ctx, client, requestURL.String(), headers)
		if err != nil {
			return nil, err
		}

		var response virusTotalResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    err,
			}
		}

		for _, item := range response.Data {
			if item.Type != "" && item.Type != "domain" {
				continue
			}

			hostname, wildcard, err := normalize.Hostname(domain, item.ID)
			if err != nil {
				continue
			}

			if seen[hostname] {
				continue
			}

			seen[hostname] = true

			evidence := model.Evidence{
				Source:     p.Name(),
				ObservedAt: observedAt,
				RecordType: "subdomain",
				Wildcard:   wildcard,
				Reference:  "https://www.virustotal.com/gui/domain/" + url.PathEscape(hostname),
			}

			if item.Attributes.FirstSeenDate > 0 {
				firstSeen := time.Unix(
					item.Attributes.FirstSeenDate, 0,
				).UTC()
				evidence.FirstSeen = &firstSeen
			}

			results = append(results, model.Result{
				URL:      hostname,
				Evidence: []model.Evidence{evidence},
			})
		}

		if response.Links.Next == "" {
			return results, nil
		}

		if len(response.Data) == 0 {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    fmt.Errorf("pagination reported more results but returned an empty page"),
			}
		}

		nextCursor := strings.TrimSpace(response.Meta.Cursor)
		if nextCursor == "" || nextCursor == cursor {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    fmt.Errorf("pagination cursor missing or did not advance"),
			}
		}

		cursor = nextCursor

		if page == virusTotalMaxPages {
			return nil, &model.ProviderError{
				Reason: "result_limit_reached",
				Err:    fmt.Errorf("maximum page limit reached"),
			}
		}
	}

	return results, nil
}
