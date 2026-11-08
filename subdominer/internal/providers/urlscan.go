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
	urlScanPageSize = 1000
	urlScanMaxPages = 50
)

// URLScanProvider searches historical URLScan website scans.
type URLScanProvider struct {
	provider.Metadata
	BaseURL string
}

type urlScanSearchResponse struct {
	Results []urlScanSearchResult `json:"results"`
	Total   int                   `json:"total"`
	HasMore bool                  `json:"has_more"`
}

type urlScanSearchResult struct {
	Task struct {
		Domain string `json:"domain"`
		URL    string `json:"url"`
		UUID   string `json:"uuid"`
		Time   string `json:"time"`
	} `json:"task"`

	Page struct {
		Domain string `json:"domain"`
		URL    string `json:"url"`
	} `json:"page"`

	Sort []json.RawMessage `json:"sort"`
}

func (r urlScanSearchResult) hostnames() []string {
	candidates := []string{
		r.Task.Domain,
		r.Page.Domain,
		urlHostname(r.Task.URL),
		urlHostname(r.Page.URL),
	}

	seen := make(map[string]bool)
	hostnames := make([]string, 0, len(candidates))

	for _, hostname := range candidates {
		hostname = strings.TrimSpace(hostname)
		if hostname == "" || seen[hostname] {
			continue
		}

		seen[hostname] = true
		hostnames = append(hostnames, hostname)
	}

	return hostnames
}

func urlHostname(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}

	return parsed.Hostname()
}

func urlScanSearchAfter(sortValues []json.RawMessage) (string, error) {
	if len(sortValues) == 0 {
		return "", fmt.Errorf("missing sort values")
	}

	values := make([]string, 0, len(sortValues))

	for _, raw := range sortValues {
		if len(raw) == 0 {
			return "", fmt.Errorf("empty sort value")
		}

		var value string
		if err := json.Unmarshal(raw, &value); err == nil {
			values = append(values, value)
			continue
		}

		// Numeric and other non-string JSON sort values.
		values = append(values, string(raw))
	}

	return strings.Join(values, ","), nil
}

func (p *URLScanProvider) Query(
	ctx context.Context,
	domain string,
	client *http.Client,
	apiKey string,
) ([]model.Result, error) {
	domain, err := normalize.Domain(domain, "")
	if err != nil {
		return nil, err
	}

	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = "https://urlscan.io"
	}

	endpoint, err := url.Parse(base + "/api/v1/search/")
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_endpoint",
			Err:    err,
		}
	}

	// Restrict matches to scans whose original or final page domain
	// belongs to the requested domain.
	searchQuery := "(page.domain:" + domain + " OR task.domain:" + domain + ")"

	headers := make(http.Header)
	apiKey = strings.TrimSpace(apiKey)
	if apiKey != "" {
		headers.Set("API-Key", apiKey)
	}

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0)
	seenresults := make(map[string]bool)

	searchAfter := ""
	fetched := 0

	for page := 1; page <= urlScanMaxPages; page++ {
		params := endpoint.Query()

		params.Set("q", searchQuery)
		params.Set("size", fmt.Sprint(urlScanPageSize))

		if searchAfter != "" {
			params.Set("search_after", searchAfter)
		}

		endpoint.RawQuery = params.Encode()

		body, err := httpclient.Get(ctx, client, endpoint.String(), headers)
		if err != nil {
			return nil, err
		}

		var response urlScanSearchResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    err,
			}
		}

		for _, result := range response.Results {
			lastSeen := provider.ParseTimestamp(result.Task.Time)

			for _, candidate := range result.hostnames() {
				hostname, wildcard, err := normalize.Hostname(
					domain,
					candidate,
				)
				if err != nil {
					// Ignore hostnames outside the requested domain.
					continue
				}

				// A single scan can mention the same hostname in
				// both task and page fields. Preserve one finding
				// per hostname per scan.
				key := hostname + "\x00" + result.Task.UUID
				if seenresults[key] {
					continue
				}

				seenresults[key] = true

				evidence := model.Evidence{
					Source:     p.Name(),
					ObservedAt: observedAt,
					RecordType: "website-scan",
					Wildcard:   wildcard,
					LastSeen:   lastSeen,
				}

				if result.Task.UUID != "" {
					evidence.Reference = "https://urlscan.io/result/" +
						url.PathEscape(result.Task.UUID) + "/"
				}

				results = append(results, model.Result{
					URL:      hostname,
					Evidence: []model.Evidence{evidence},
				})
			}
		}

		fetched += len(response.Results)

		// URLScan caps the exact total at 10,000 and sets has_more
		// when additional results exist beyond that count.
		needsNextPage := response.HasMore || fetched < response.Total
		if !needsNextPage {
			break
		}

		if len(response.Results) == 0 {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    fmt.Errorf("pagination reported more results but returned an empty page"),
			}
		}

		cursor, err := urlScanSearchAfter(
			response.Results[len(response.Results)-1].Sort,
		)
		if err != nil {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    err,
			}
		}

		if cursor == searchAfter {
			return nil, &model.ProviderError{
				Reason: "invalid_response",
				Err:    fmt.Errorf("pagination cursor did not advance"),
			}
		}

		searchAfter = cursor

		if page == urlScanMaxPages {
			return nil, &model.ProviderError{
				Reason: "result_limit_reached",
				Err:    fmt.Errorf("maximum page limit reached"),
			}
		}
	}

	return results, nil
}
