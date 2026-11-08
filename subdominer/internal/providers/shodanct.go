package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
)

type ShodanCTProvider struct {
	provider.Metadata
	BaseURL string
}

func (p *ShodanCTProvider) Query(
	ctx context.Context,
	domain string,
	client *http.Client,
	_ string,
) ([]model.Result, error) {
	domain, err := normalize.Domain(domain, "")
	if err != nil {
		return nil, err
	}

	base := strings.TrimRight(p.BaseURL, "/")
	if base == "" {
		base = "https://ctl.shodan.io"
	}

	endpoint := base + "/api/v1/domain/" +
		url.PathEscape(domain) + "/hostnames"

	body, err := httpclient.Get(ctx, client, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var hostnames []string
	if err := json.Unmarshal(body, &hostnames); err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_response",
			Err:    err,
		}
	}

	observedAt := time.Now().UTC()
	results := make([]model.Result, 0, len(hostnames))

	for _, hostname := range hostnames {
		normalized, wildcard, err := normalize.Hostname(domain, hostname)
		if err != nil {
			continue
		}

		results = append(results, model.Result{
			URL: normalized,
			Evidence: []model.Evidence{
				{
					Source:     p.Name(),
					ObservedAt: observedAt,
					RecordType: "certificate-transparency",
					Wildcard:   wildcard,
				},
			},
		})
	}

	return results, nil
}
