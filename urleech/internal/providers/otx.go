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
	otxEndpoint = "https://otx.alienvault.com"
	otxMaxPages = 20
)

type OTXProvider struct {
	provider.Metadata
	BaseURL string
}

type otxResponse struct {
	URLList []struct {
		URL      string `json:"url"`
		Date     string `json:"date"`
		HTTPCode int    `json:"httpcode"`
	} `json:"url_list"`
	HasNext bool `json:"has_next"`
}

func (p *OTXProvider) Query(ctx context.Context, domain string, client *http.Client, apiKey string) ([]model.Result, error) {
	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = otxEndpoint
	}

	observed := time.Now().UTC()
	results := make([]model.Result, 0)
	seenPages := make(map[string]bool)

	for page := 1; page <= otxMaxPages; page++ {
		if page > 1 {
			if err := provider.Wait(ctx, 250*time.Millisecond); err != nil {
				return nil, &model.ProviderError{Reason: "request_failed", Err: err}
			}
		}

		endpoint, err := url.Parse(base + "/api/v1/indicators/domain/" + url.PathEscape(domain) + "/url_list")
		if err != nil {
			return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
		}

		params := endpoint.Query()
		params.Set("page", strconv.Itoa(page))

		endpoint.RawQuery = params.Encode()

		headers := make(http.Header)
		if strings.TrimSpace(apiKey) != "" {
			headers.Set("X-OTX-API-KEY", strings.TrimSpace(apiKey))
		}

		body, err := httpclient.Get(ctx, client, endpoint.String(), headers)
		if err != nil {
			return nil, err
		}

		var response otxResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, &model.ProviderError{Reason: "invalid_response", Err: err}
		}

		for _, item := range response.URLList {
			normalized, err := normalize.URL(item.URL, domain)
			if err != nil {
				continue
			}

			key := normalized + "\x00" + item.Date
			if seenPages[key] {
				continue
			}

			seenPages[key] = true

			e := model.Evidence{
				Source:     p.Name(),
				ObservedAt: observed,
				SourceTime: provider.ParseTimestamp(item.Date),
				RecordType: "threat-intelligence-url",
				StatusCode: item.HTTPCode,
			}

			e.Reference = "https://otx.alienvault.com/indicator/domain/" + url.PathEscape(domain)

			results = append(results, model.Result{Domain: domain, URL: normalized, Evidence: []model.Evidence{e}})
		}

		if !response.HasNext {
			break
		}

		if len(response.URLList) == 0 {
			return nil, &model.ProviderError{Reason: "invalid_response", Err: fmt.Errorf("pagination continued with an empty page")}
		}

		if page == otxMaxPages {
			return nil, &model.ProviderError{Reason: "result_limit_reached", Err: fmt.Errorf("maximum page limit reached")}
		}
	}

	return results, nil
}
