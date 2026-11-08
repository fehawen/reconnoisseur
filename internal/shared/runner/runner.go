package runner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/aggregate"
	"github.com/fehawen/reconnoisseur/internal/shared/logging"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
)

const providerTimeout = 2 * time.Minute

type Provider interface {
	Name() string
	APIKeyEnv() string
	RequiresAPIKey() bool
	Query(
		ctx context.Context,
		domain string,
		client *http.Client,
		apiKey string,
	) ([]model.Result, error)
}

type Runner struct {
	providers      []Provider
	aggregator     *aggregate.Aggregator
	logger         *logging.Logger
	client         *http.Client
	lookupEnv      func(string) string
	timeout        time.Duration
	prepareResults func(string, string, []model.Result) ([]model.Result, error)
}

func New(
	providers []Provider,
	aggregator *aggregate.Aggregator,
	logger *logging.Logger,
	prepareResults func(string, string, []model.Result) ([]model.Result, error),
) *Runner {
	return &Runner{
		providers:      providers,
		aggregator:     aggregator,
		logger:         logger,
		client:         &http.Client{Timeout: providerTimeout},
		lookupEnv:      os.Getenv,
		timeout:        providerTimeout,
		prepareResults: prepareResults,
	}
}

func (r *Runner) RunDomain(ctx context.Context, domain string) error {
	if r == nil {
		return errors.New("provider runner is nil")
	}

	if ctx == nil {
		return errors.New("context is nil")
	}

	if r.logger == nil {
		return errors.New("logger is nil")
	}

	if r.client == nil {
		return errors.New("HTTP client is nil")
	}

	if r.lookupEnv == nil {
		return errors.New("environment lookup is nil")
	}

	if r.timeout <= 0 {
		return errors.New("provider timeout must be positive")
	}

	if r.prepareResults == nil {
		return errors.New("results preparation function is nil")
	}

	domain, err := normalize.Domain(domain, "")
	if err != nil {
		return err
	}

	seen := make(map[string]bool)

	for _, provider := range r.providers {
		if err := ctx.Err(); err != nil {
			return err
		}

		if provider == nil {
			return errors.New("provider list contains nil")
		}

		name := strings.TrimSpace(provider.Name())
		if name == "" || seen[name] {
			return fmt.Errorf("empty or duplicate provider name %q", name)
		}

		seen[name] = true

		keyEnv := strings.TrimSpace(provider.APIKeyEnv())
		if provider.RequiresAPIKey() && keyEnv == "" {
			return fmt.Errorf("provider %q requires an API key but has no environment variable configured", name)
		}

		apiKey := ""
		if keyEnv != "" {
			apiKey = r.lookupEnv(keyEnv)
		}

		if provider.RequiresAPIKey() && strings.TrimSpace(apiKey) == "" {
			if err := r.logger.LogProvider(name, domain, model.StatusSkipped, 0, "missing_api_key"); err != nil {
				return err
			}

			continue
		}

		timeout := r.timeout
		if timeout <= 0 {
			timeout = providerTimeout
		}

		providerCtx, cancel := context.WithTimeout(ctx, timeout)
		results, queryErr := provider.Query(providerCtx, domain, r.client, apiKey)

		cancel()

		if queryErr != nil {
			if err := ctx.Err(); err != nil {
				return err
			}

			if err := r.logger.LogProvider(name, domain, model.StatusError, 0, providerErrorReason(queryErr)); err != nil {
				return err
			}

			continue
		}

		prepared, err := r.prepareResults(name, domain, results)
		if err != nil {
			if logErr := r.logger.LogProvider(name, domain, model.StatusError, 0, "invalid_response"); logErr != nil {
				return logErr
			}

			continue
		}

		if len(prepared) == 0 {
			if err := r.logger.LogProvider(name, domain, model.StatusEmpty, 0, ""); err != nil {
				return err
			}

			continue
		}

		for _, result := range prepared {
			if err := r.aggregator.Add(result); err != nil {
				return fmt.Errorf("aggregate result from %q: %w", name, err)
			}
		}

		if err := r.logger.LogProvider(name, domain, model.StatusSuccess, len(prepared), ""); err != nil {
			return err
		}
	}

	return nil
}

func providerErrorReason(err error) string {
	var providerErr *model.ProviderError
	if errors.As(err, &providerErr) && providerErr.Reason != "" {
		reason := strings.TrimSpace(providerErr.Reason)
		if len(reason) <= 80 {
			for _, c := range reason {
				if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
					continue
				}

				return "provider_error"
			}

			return reason
		}
	}

	return "provider_error"
}
