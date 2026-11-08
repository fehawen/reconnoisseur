package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
)

const (
	commonCrawlCollectionsEndpoint = "https://index.commoncrawl.org/collinfo.json"
	commonCrawlResultLimit         = 10000
)

type CommonCrawlProvider struct {
	provider.Metadata
	collectionsEndpoint string
	mu                  sync.Mutex
	indexURL            string
}

func (p *CommonCrawlProvider) Query(
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

	indexURL, err := p.latestIndexURL(ctx, client)
	if err != nil {
		return nil, err
	}

	endpoint, err := url.Parse(indexURL)
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_index_url",
			Err:    err,
		}
	}

	params := endpoint.Query()

	params.Set("url", domain)
	params.Set("matchType", "domain")
	params.Set("output", "json")
	params.Set("fl", "url,timestamp")
	params.Set("limit", fmt.Sprint(commonCrawlResultLimit))

	endpoint.RawQuery = params.Encode()

	body, err := httpclient.Get(ctx, client, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	var results []model.Result
	decoder := json.NewDecoder(bytes.NewReader(body))
	observedAt := time.Now().UTC()

	for {
		var record struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}

		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, &model.ProviderError{
				Reason: "invalid_json",
				Err:    err,
			}
		}

		parsedURL, err := url.Parse(record.URL)
		if err != nil || parsedURL.Hostname() == "" {
			continue
		}

		hostname, wildcard, err := normalize.Hostname(
			domain,
			parsedURL.Hostname(),
		)
		if err != nil {
			continue
		}

		capturedAt := provider.ParseTimestamp(record.Timestamp)

		referenceURL, err := url.Parse(indexURL)
		if err != nil {
			return nil, &model.ProviderError{
				Reason: "invalid_index_url",
				Err:    err,
			}
		}

		referenceQuery := referenceURL.Query()
		referenceQuery.Set("url", record.URL)
		referenceQuery.Set("output", "json")
		referenceURL.RawQuery = referenceQuery.Encode()

		results = append(results, model.Result{
			URL: hostname,
			Evidence: []model.Evidence{
				{
					Source:     p.Name(),
					ObservedAt: observedAt,
					FirstSeen:  capturedAt,
					RecordType: "archived-url",
					Reference:  referenceURL.String(),
					Wildcard:   wildcard,
				},
			},
		})
	}

	return results, nil
}

func (p *CommonCrawlProvider) latestIndexURL(
	ctx context.Context,
	client *http.Client,
) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.indexURL != "" {
		return p.indexURL, nil
	}

	endpoint := p.collectionsEndpoint
	if endpoint == "" {
		endpoint = commonCrawlCollectionsEndpoint
	}

	body, err := httpclient.Get(ctx, client, endpoint, nil)
	if err != nil {
		return "", err
	}

	var collections []struct {
		ID     string `json:"id"`
		CDXAPI string `json:"cdx-api"`
	}

	if err := json.Unmarshal(body, &collections); err != nil {
		return "", &model.ProviderError{
			Reason: "invalid_collections_json",
			Err:    err,
		}
	}

	if len(collections) == 0 || collections[0].CDXAPI == "" {
		return "", &model.ProviderError{
			Reason: "index_unavailable",
		}
	}

	p.indexURL = collections[0].CDXAPI

	return p.indexURL, nil
}
