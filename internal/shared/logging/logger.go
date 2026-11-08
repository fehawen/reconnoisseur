package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/model"
)

type Entry struct {
	Timestamp time.Time            `json:"timestamp"`
	Provider  string               `json:"provider"`
	Domain    string               `json:"domain"`
	Status    model.ProviderStatus `json:"status"`
	Results   int                  `json:"results,omitempty"`
	Reason    string               `json:"reason,omitempty"`
}

type Logger struct {
	mu       sync.Mutex
	file     *os.File
	disabled bool
	closed   bool
}

func New(path string, silent bool) (*Logger, error) {
	if silent {
		return &Logger{disabled: true}, nil
	}

	if strings.TrimSpace(path) == "" {
		return nil, errors.New("log path is empty")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}

	return &Logger{file: f}, nil
}

func (l *Logger) LogProvider(provider, domain string, status model.ProviderStatus, count int, reason string) error {
	if l == nil {
		return errors.New("logger is nil")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.disabled {
		return nil
	}

	if l.closed {
		return errors.New("logger is closed")
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

	entry := Entry{
		Timestamp: time.Now().UTC(),
		Provider:  provider,
		Domain:    domain,
		Status:    status,
		Results:   count,
		Reason:    reason,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	data = append(data, '\n')
	if _, err := l.file.Write(data); err != nil {
		return fmt.Errorf("write log: %w", err)
	}

	return nil
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.disabled || l.closed {
		return nil
	}

	l.closed = true

	return l.file.Close()
}
