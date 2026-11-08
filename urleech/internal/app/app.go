package app

import (
	"fmt"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/app"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
	"github.com/fehawen/reconnoisseur/internal/shared/runner"
	"github.com/fehawen/reconnoisseur/urleech/internal/providers"
)

func Run() error {
	providerList := []runner.Provider{
		&providers.CommonCrawlProvider{
			Metadata: provider.Metadata{
				ProviderName:   "commoncrawl",
				APIKeyEnvName:  "",
				APIKeyRequired: false,
			},
		},
		&providers.OTXProvider{
			Metadata: provider.Metadata{
				ProviderName:   "otx",
				APIKeyEnvName:  "OTX_API_KEY",
				APIKeyRequired: false,
			},
		},
		&providers.URLScanProvider{
			Metadata: provider.Metadata{
				ProviderName:   "urlscan",
				APIKeyEnvName:  "URLSCAN_API_KEY",
				APIKeyRequired: false,
			},
		},
		&providers.VirusTotalProvider{
			Metadata: provider.Metadata{
				ProviderName:   "virustotal",
				APIKeyEnvName:  "VIRUSTOTAL_API_KEY",
				APIKeyRequired: true,
			},
		},
		&providers.WaybackProvider{
			Metadata: provider.Metadata{
				ProviderName:   "wayback",
				APIKeyEnvName:  "",
				APIKeyRequired: false,
			},
		},
	}

	return app.Run(
		"urleech",
		providerList,
		normalize.URL,
		prepareResults,
	)
}

func prepareResults(providerName, domain string, results []model.Result) ([]model.Result, error) {
	prepared := make([]model.Result, 0, len(results))
	observedAt := time.Now().UTC()

	for _, result := range results {
		if result.Domain == "" {
			result.Domain = domain
		}

		resultDomain, err := normalize.Domain(result.Domain, "")
		if err != nil || resultDomain != domain {
			return nil, fmt.Errorf("provider returned a result for an unexpected domain")
		}

		normalizedURL, err := normalize.URL(result.URL, domain)
		if err != nil {
			return nil, fmt.Errorf("provider returned an invalid URL")
		}

		if len(result.Evidence) == 0 {
			return nil, fmt.Errorf("provider returned a URL without evidence")
		}

		result.SchemaVersion = model.SchemaVersion
		result.Domain = domain
		result.URL = normalizedURL

		for i := range result.Evidence {
			evidence := &result.Evidence[i]
			if evidence.Source != "" && evidence.Source != providerName {
				return nil, fmt.Errorf("provider returned evidence attributed to another source")
			}

			evidence.Source = providerName

			if evidence.ObservedAt.IsZero() {
				evidence.ObservedAt = observedAt
			} else {
				evidence.ObservedAt = evidence.ObservedAt.UTC()
			}

			if evidence.SourceTime != nil {
				t := evidence.SourceTime.UTC()
				evidence.SourceTime = &t
			}
		}

		prepared = append(prepared, result)
	}

	return prepared, nil
}
