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
	waybackEndpoint = "https://web.archive.org/cdx/search/cdx"
	waybackLimit    = 10000
)

type WaybackProvider struct {
	provider.Metadata
	BaseURL string
}

func (p *WaybackProvider) Query(ctx context.Context, domain string, client *http.Client, _ string) ([]model.Result, error) {
	base := p.BaseURL
	if base == "" {
		base = waybackEndpoint
	}

	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
	}

	params := u.Query()
	params.Set("url", domain)
	params.Set("matchType", "domain")
	params.Set("output", "json")
	params.Set("fl", "timestamp,original,statuscode,mimetype")
	params.Set("collapse", "urlkey")
	params.Set("limit", strconv.Itoa(waybackLimit))
	u.RawQuery = params.Encode()

	body, err := httpclient.Get(ctx, client, u.String(), nil)
	if err != nil {
		return nil, err
	}

	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, &model.ProviderError{Reason: "invalid_response", Err: err}
	}

	if len(rows) < 2 {
		return nil, nil
	}

	indices := map[string]int{}
	for i, field := range rows[0] {
		indices[field] = i
	}

	for _, field := range []string{"timestamp", "original"} {
		if _, ok := indices[field]; !ok {
			return nil, &model.ProviderError{Reason: "invalid_response", Err: fmt.Errorf("missing CDX field %q", field)}
		}
	}

	observed := time.Now().UTC()
	results := make([]model.Result, 0, len(rows)-1)
	for _, row := range rows[1:] {
		if indices["timestamp"] >= len(row) || indices["original"] >= len(row) {
			continue
		}

		rawURL := strings.TrimSpace(row[indices["original"]])

		normalized, err := normalize.URL(rawURL, domain)
		if err != nil {
			continue
		}

		e := model.Evidence{
			Source:     p.Name(),
			ObservedAt: observed,
			SourceTime: provider.ParseTimestamp(row[indices["timestamp"]]),
			RecordType: "archive-capture",
		}

		if i, ok := indices["statuscode"]; ok && i < len(row) {
			e.StatusCode, _ = strconv.Atoi(row[i])
		}

		if i, ok := indices["mimetype"]; ok && i < len(row) {
			e.ContentType = row[i]
		}

		ts := row[indices["timestamp"]]
		if ts != "" {
			e.Reference = "https://web.archive.org/web/" + ts + "/" + rawURL
		}

		results = append(results, model.Result{Domain: domain, URL: normalized, Evidence: []model.Evidence{e}})
	}

	return results, nil
}
