package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
)

const (
	commonCrawlCollections = "https://index.commoncrawl.org/collinfo.json"
	commonCrawlMaxIndexes  = 3
	commonCrawlLimit       = 5000
)

type CommonCrawlProvider struct {
	provider.Metadata
	CollectionsURL string
	MaxIndexes     int
}

type commonCrawlIndex struct {
	ID     string `json:"id"`
	CDXAPI string `json:"cdx-api"`
}

type commonCrawlRecord struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
	Mime      string `json:"mime"`
}

func (p *CommonCrawlProvider) Query(ctx context.Context, domain string, client *http.Client, _ string) ([]model.Result, error) {
	collectionsURL := p.CollectionsURL
	if collectionsURL == "" {
		collectionsURL = commonCrawlCollections
	}

	body, err := httpclient.Get(ctx, client, collectionsURL, nil)
	if err != nil {
		return nil, err
	}

	var indexes []commonCrawlIndex
	if err := json.Unmarshal(body, &indexes); err != nil {
		return nil, &model.ProviderError{Reason: "invalid_collections_response", Err: err}
	}

	if len(indexes) == 0 {
		return nil, &model.ProviderError{Reason: "no_indexes"}
	}

	maxIndexes := p.MaxIndexes
	if maxIndexes <= 0 {
		maxIndexes = commonCrawlMaxIndexes
	}

	if len(indexes) > maxIndexes {
		indexes = indexes[:maxIndexes]
	}

	observed := time.Now().UTC()
	results := make([]model.Result, 0)

	// Query both the apex host and its subdomains. Common Crawl's CDX
	// interface accepts wildcard URL patterns for domain-wide searches.
	patterns := []string{domain + "/*", "*." + domain + "/*"}

	requestCount := 0
	for _, index := range indexes {
		if index.CDXAPI == "" {
			continue
		}
		for _, pattern := range patterns {
			endpoint, err := url.Parse(index.CDXAPI)
			if err != nil {
				return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
			}

			query := endpoint.Query()
			query.Set("url", pattern)
			query.Set("output", "json")
			query.Set("fl", "url,timestamp,status,mime")
			query.Set("limit", fmt.Sprint(commonCrawlLimit))

			endpoint.RawQuery = query.Encode()

			if requestCount > 0 {
				if err := provider.Wait(ctx, 500*time.Millisecond); err != nil {
					return nil, &model.ProviderError{Reason: "request_failed", Err: err}
				}
			}

			requestCount++
			data, err := httpclient.Get(ctx, client, endpoint.String(), nil)
			if err != nil {
				return nil, err
			}

			scanner := bufio.NewScanner(bytes.NewReader(data))
			scanner.Buffer(make([]byte, 4096), 2<<20)

			for scanner.Scan() {
				var record commonCrawlRecord
				if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
					return nil, &model.ProviderError{Reason: "invalid_response", Err: err}
				}

				normalized, err := normalize.URL(record.URL, domain)
				if err != nil {
					continue
				}

				e := model.Evidence{
					Source:     p.Name(),
					ObservedAt: observed,
					SourceTime: provider.ParseTimestamp(record.Timestamp),
					RecordType: "web-crawl",
					Reference:  index.ID,
				}

				e.StatusCode, _ = strconv.Atoi(record.Status)
				e.ContentType = record.Mime

				results = append(results, model.Result{Domain: domain, URL: normalized, Evidence: []model.Evidence{e}})
			}

			if err := scanner.Err(); err != nil {
				return nil, &model.ProviderError{Reason: "response_read_failed", Err: err}
			}
		}
	}
	return results, nil
}
