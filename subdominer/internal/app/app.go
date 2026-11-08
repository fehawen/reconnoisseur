package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/app"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/provider"
	"github.com/fehawen/reconnoisseur/internal/shared/runner"
	"github.com/fehawen/reconnoisseur/subdominer/internal/providers"
)

func Run() error {
	providerList := []runner.Provider{
		&providers.CertSpotterProvider{
			Metadata: provider.Metadata{
				ProviderName:   "certspotter",
				APIKeyEnvName:  "CERTSPOTTER_API_KEY",
				APIKeyRequired: false,
			},
		},
		&providers.CommonCrawlProvider{
			Metadata: provider.Metadata{
				ProviderName:   "commoncrawl",
				APIKeyEnvName:  "",
				APIKeyRequired: false,
			},
		},
		&providers.CRTNameProvider{
			Metadata: provider.Metadata{
				ProviderName:   "crt.name",
				APIKeyEnvName:  "",
				APIKeyRequired: false,
			},
		},
		&providers.CRTShProvider{
			Metadata: provider.Metadata{
				ProviderName:   "crt.sh",
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
		&providers.PDChaosProvider{
			Metadata: provider.Metadata{
				ProviderName:   "pd-chaos",
				APIKeyEnvName:  "PDCP_API_KEY",
				APIKeyRequired: true,
			},
		},
		&providers.ShodanCTProvider{
			Metadata: provider.Metadata{
				ProviderName:   "shodan-ct",
				APIKeyEnvName:  "",
				APIKeyRequired: false,
			},
		},
		&providers.ShodanDNSProvider{
			Metadata: provider.Metadata{
				ProviderName:   "shodan-dns",
				APIKeyEnvName:  "SHODAN_API_KEY",
				APIKeyRequired: true,
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
		"subdominer",
		providerList,
		normalize.Domain,
		prepareResults,
	)
}

func prepareResults(
	providerName string,
	domain string,
	findings []model.Result,
) ([]model.Result, error) {
	normalizedDomain, err := normalize.Domain(domain, "")
	if err != nil {
		return nil, err
	}

	observedAt := time.Now().UTC()
	resultsByHostname := make(map[string]*model.Result)

	for _, finding := range findings {
		hostname, wildcard, err := normalize.Hostname(
			normalizedDomain,
			finding.URL,
		)
		if err != nil {
			return nil, err
		}

		if len(finding.Evidence) == 0 {
			return nil, fmt.Errorf(
				"hostname %q has no evidence",
				hostname,
			)
		}

		result, exists := resultsByHostname[hostname]
		if !exists {
			result = &model.Result{
				SchemaVersion: model.SchemaVersion,
				Domain:        normalizedDomain,
				URL:           hostname,
			}
			resultsByHostname[hostname] = result
		}

		for _, item := range finding.Evidence {
			source := strings.TrimSpace(item.Source)
			if source != "" && source != providerName {
				return nil, fmt.Errorf(
					"evidence source %q does not match provider %q",
					source,
					providerName,
				)
			}

			item.Source = providerName

			if item.ObservedAt.IsZero() {
				item.ObservedAt = observedAt
			} else {
				item.ObservedAt = item.ObservedAt.UTC()
			}

			if item.ValidFrom != nil {
				t := item.ValidFrom.UTC()
				item.ValidFrom = &t
			}

			if item.ValidUntil != nil {
				t := item.ValidUntil.UTC()
				item.ValidUntil = &t
			}

			if item.FirstSeen != nil {
				t := item.FirstSeen.UTC()
				item.FirstSeen = &t
			}

			if item.LastSeen != nil {
				t := item.LastSeen.UTC()
				item.LastSeen = &t
			}

			if wildcard {
				item.Wildcard = true
			} else if item.Wildcard {
				return nil, fmt.Errorf(
					"concrete hostname %q has wildcard evidence",
					hostname,
				)
			}

			result.Evidence = append(result.Evidence, item)
		}
	}

	results := make([]model.Result, 0, len(resultsByHostname))
	for _, res := range resultsByHostname {
		results = append(results, *res)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].URL < results[j].URL
	})

	return results, nil
}
