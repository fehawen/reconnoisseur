package providers

import (
	"context"
	"encoding/json"
	"fmt"
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
	virusTotalEndpoint = "https://www.virustotal.com"
	virusTotalPageSize = 40
	virusTotalMaxPages = 10
)

type VirusTotalProvider struct {
	provider.Metadata
	BaseURL string
}

type virusTotalResponse struct {
	Data []struct {
		Attributes struct {
			URL                  string `json:"url"`
			FirstSubmissionDate  int64  `json:"first_submission_date"`
			LastSubmissionDate   int64  `json:"last_submission_date"`
			LastHTTPResponseCode int    `json:"last_http_response_code"`
		} `json:"attributes"`
	} `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
}

func (p *VirusTotalProvider) Query(ctx context.Context, domain string, client *http.Client, apiKey string) ([]model.Result, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, &model.ProviderError{Reason: "missing_api_key"}
	}

	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = virusTotalEndpoint
	}

	endpoint := base + "/api/v3/domains/" + url.PathEscape(domain) + "/urls"
	headers := make(http.Header)
	headers.Set("x-apikey", strings.TrimSpace(apiKey))
	observed := time.Now().UTC()
	results := make([]model.Result, 0)
	seen := make(map[string]bool)
	cursor := ""

	for page := 1; page <= virusTotalMaxPages; page++ {
		u, err := url.Parse(endpoint)
		if err != nil {
			return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
		}

		params := u.Query()
		params.Set("limit", strconv.Itoa(virusTotalPageSize))

		if cursor != "" {
			params.Set("cursor", cursor)
		}

		u.RawQuery = params.Encode()
		body, err := httpclient.Get(ctx, client, u.String(), headers)
		if err != nil {
			return nil, err
		}

		var response virusTotalResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, &model.ProviderError{Reason: "invalid_response", Err: err}
		}

		for _, item := range response.Data {
			normalized, err := normalize.URL(item.Attributes.URL, domain)
			if err != nil || seen[normalized] {
				continue
			}

			seen[normalized] = true

			sourceTime := item.Attributes.LastSubmissionDate
			if sourceTime == 0 {
				sourceTime = item.Attributes.FirstSubmissionDate
			}

			var observedSource *time.Time
			if sourceTime > 0 {
				t := time.Unix(sourceTime, 0).UTC()
				observedSource = &t
			}

			e := model.Evidence{
				Source:     p.Name(),
				ObservedAt: observed,
				SourceTime: observedSource,
				RecordType: "domain-url",
				Reference:  "https://www.virustotal.com/gui/domain/" + domain,
				StatusCode: item.Attributes.LastHTTPResponseCode,
			}

			results = append(results, model.Result{Domain: domain, URL: normalized, Evidence: []model.Evidence{e}})
		}

		if response.Links.Next == "" {
			break
		}

		if len(response.Data) == 0 {
			return nil, &model.ProviderError{Reason: "invalid_response", Err: fmt.Errorf("pagination continued with an empty page")}
		}

		nextCursor := strings.TrimSpace(response.Meta.Cursor)
		if nextCursor == "" && response.Links.Next != "" {
			nextURL, parseErr := url.Parse(response.Links.Next)
			if parseErr == nil {
				nextCursor = nextURL.Query().Get("cursor")
			}
		}

		if nextCursor == "" || nextCursor == cursor {
			return nil, &model.ProviderError{Reason: "invalid_response", Err: fmt.Errorf("pagination cursor missing or did not advance")}
		}

		cursor = nextCursor
		if page == virusTotalMaxPages {
			return nil, &model.ProviderError{Reason: "result_limit_reached", Err: fmt.Errorf("maximum page limit reached")}
		}
	}

	return results, nil
}
