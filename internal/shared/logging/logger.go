package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func (l *Logger) Write(v any) error {
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

	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal log entry: %w", err)
	}

	data = append(data, '\n')

	n, err := l.file.Write(data)
	if err != nil {
		return fmt.Errorf("write log: %w", err)
	}

	if n != len(data) {
		return io.ErrShortWrite
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
