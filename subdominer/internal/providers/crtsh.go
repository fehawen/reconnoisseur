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

type CRTShProvider struct {
	provider.Metadata
	BaseURL string
}

type crtSHRecord struct {
	ID         int64  `json:"id"`
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

func (p *CRTShProvider) Query(
	ctx context.Context,
	domain string,
	client *http.Client,
	_ string,
) ([]model.Result, error) {
	domain, err := normalize.Domain(domain, "")
	if err != nil {
		return nil, err
	}

	base := p.BaseURL
	if base == "" {
		base = "https://crt.sh/"
	}

	endpoint, err := url.Parse(base)
	if err != nil {
		return nil, &model.ProviderError{Reason: "invalid_endpoint", Err: err}
	}

	params := endpoint.Query()

	params.Set("q", "%."+domain)
	params.Set("output", "json")

	endpoint.RawQuery = params.Encode()

	body, err := httpclient.Get(ctx, client, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	var records []crtSHRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_response",
			Err:    err,
		}
	}

	results := make([]model.Result, 0)
	observedAt := time.Now().UTC()

	for _, record := range records {
		names := strings.FieldsFunc(
			record.NameValue+"\n"+record.CommonName,
			func(r rune) bool {
				return r == '\n' || r == '\r' || r == ','
			},
		)

		validFrom := provider.ParseTimestamp(record.NotBefore)
		validUntil := provider.ParseTimestamp(record.NotAfter)

		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}

			hostname, wildcard, err := normalize.Hostname(domain, name)
			if err != nil {
				// A certificate can contain names outside the queried domain.
				// They are not results for this domain.
				continue
			}

			evidence := model.Evidence{
				Source:     p.Name(),
				ObservedAt: observedAt,
				RecordType: "certificate",
				Wildcard:   wildcard,
			}

			if record.ID > 0 {
				evidence.Reference = "https://crt.sh/?id=" +
					strconv.FormatInt(record.ID, 10)
			}

			if validFrom != nil {
				evidence.ValidFrom = validFrom
			}

			if validUntil != nil {
				evidence.ValidUntil = validUntil
			}

			results = append(results, model.Result{
				URL:      hostname,
				Evidence: []model.Evidence{evidence},
			})
		}
	}

	return results, nil
}
