package logging

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/model"
)

func (l *Logger) LogProvider(
	provider, domain string,
	status model.ProviderStatus,
	count int,
	reason string,
) error {
	if l == nil {
		return errors.New("logger is nil")
	}

	provider = strings.TrimSpace(provider)
	domain = strings.TrimSpace(domain)
	reason = strings.TrimSpace(reason)

	if provider == "" {
		return errors.New("provider is empty")
	}

	if domain == "" {
		return errors.New("domain is empty")
	}

	switch status {
	case model.StatusSuccess:
		if count < 1 || reason != "" {
			return errors.New("invalid successful provider status")
		}
	case model.StatusEmpty:
		if count != 0 || reason != "" {
			return errors.New("invalid empty provider status")
		}
	case model.StatusError, model.StatusSkipped:
		if count != 0 || reason == "" {
			return errors.New("invalid error or skipped provider status")
		}
	default:
		return fmt.Errorf("invalid provider status %q", status)
	}

	return l.Write(Entry{
		Timestamp: time.Now().UTC(),
		Provider:  provider,
		Domain:    domain,
		Status:    status,
		Results:   count,
		Reason:    reason,
	})
}
