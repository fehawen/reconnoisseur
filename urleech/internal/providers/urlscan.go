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
	urlScanEndpoint   = "https://urlscan.io"
	urlScanPageSize   = 100
	urlScanMaxPages   = 5
	urlScanMaxDetails = 50
)

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
		URL  string `json:"url"`
		UUID string `json:"uuid"`
		Time string `json:"time"`
	} `json:"task"`

	Page struct {
		URL string `json:"url"`
	} `json:"page"`

	Sort []json.RawMessage `json:"sort"`
}

type urlScanDetail struct {
	Data struct {
		Requests []struct {
			Request struct {
				URL string `json:"url"`
			} `json:"request"`

			Response struct {
				Status int `json:"status"`
			} `json:"response"`
		} `json:"requests"`
	} `json:"data"`
}

func (p *URLScanProvider) Query(ctx context.Context, domain string, client *http.Client, apiKey string) ([]model.Result, error) {
	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = urlScanEndpoint
	}

	headers := make(http.Header)
	if strings.TrimSpace(apiKey) != "" {
		headers.Set("API-Key", strings.TrimSpace(apiKey))
	}

	observed := time.Now().UTC()
	results := make([]model.Result, 0)
	seen := make(map[string]map[string]bool)
	add := func(raw, recordType, reference string, sourceTime *time.Time, status int) {
		normalized, err := normalize.URL(raw, domain)
		if err != nil {
			return
		}

		key := normalized
		if seen[key] == nil {
			seen[key] = make(map[string]bool)
		}

		evidenceKey := recordType + "\x00" + reference + "\x00" + fmt.Sprint(sourceTime)
		if seen[key][evidenceKey] {
			return
		}

		seen[key][evidenceKey] = true

		e := model.Evidence{
			Source:     p.Name(),
			ObservedAt: observed,
			SourceTime: sourceTime,
			RecordType: recordType,
			Reference:  reference,
			StatusCode: status,
		}

		results = append(results, model.Result{Domain: domain, URL: normalized, Evidence: []model.Evidence{e}})
	}

	searchAfter := ""
	detailCount := 0

	for page := 1; page <= urlScanMaxPages; page++ {
		endpoint, err := url.Parse(base + "/api/v1/search/")
		if err != nil {
			return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
		}

		params := endpoint.Query()
		params.Set("q", "domain:"+domain)
		params.Set("size", strconv.Itoa(urlScanPageSize))

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
			return nil, &model.ProviderError{Reason: "invalid_response", Err: err}
		}

		for _, scan := range response.Results {
			sourceTime := provider.ParseTimestamp(scan.Task.Time)
			reference := ""

			if scan.Task.UUID != "" {
				reference = base + "/result/" + url.PathEscape(scan.Task.UUID) + "/"
			}

			add(scan.Task.URL, "scan-target", reference, sourceTime, 0)
			add(scan.Page.URL, "scan-page", reference, sourceTime, 0)

			if scan.Task.UUID == "" || detailCount >= urlScanMaxDetails {
				continue
			}

			if detailCount > 0 {
				if err := provider.Wait(ctx, 500*time.Millisecond); err != nil {
					return nil, &model.ProviderError{Reason: "request_failed", Err: err}
				}
			}

			detailURL := base + "/api/v1/result/" + url.PathEscape(scan.Task.UUID) + "/"
			detailBody, detailErr := httpclient.Get(ctx, client, detailURL, headers)
			detailCount++

			if detailErr != nil {
				continue
			}

			var detail urlScanDetail
			if json.Unmarshal(detailBody, &detail) != nil {
				continue
			}

			for _, request := range detail.Data.Requests {
				add(request.Request.URL, "scan-request", reference, sourceTime, request.Response.Status)
			}
		}

		if len(response.Results) < urlScanPageSize {
			break
		}

		cursor, err := urlScanCursor(response.Results[len(response.Results)-1].Sort)
		if err != nil {
			break
		}

		if cursor == searchAfter {
			break
		}

		searchAfter = cursor
		if detailCount >= urlScanMaxDetails {
			break
		}

		if page == urlScanMaxPages {
			break
		}
	}

	return results, nil
}

func urlScanCursor(values []json.RawMessage) (string, error) {
	if len(values) == 0 {
		return "", fmt.Errorf("missing sort values")
	}

	out := make([]string, 0, len(values))

	for _, raw := range values {
		var s string

		if json.Unmarshal(raw, &s) == nil {
			out = append(out, s)
		} else {
			out = append(out, string(raw))
		}
	}

	return strings.Join(out, ","), nil
}
