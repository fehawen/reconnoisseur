package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/logging"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/probator/internal/probe"
)

const (
	inputSchemaVersion = 1
	defaultWorkers     = 20
)

type Config struct {
	Workers int
	Probe   probe.Config
	LogPath string
	Silent  bool
}

func DefaultConfig() Config {
	return Config{
		Workers: defaultWorkers,
		Probe:   probe.DefaultConfig(),
		LogPath: "./probator.log",
	}
}

type prober interface {
	Probe(context.Context, string) (probe.Result, error)
}

type inputRecord = model.Result

type outputRecord struct {
	SchemaVersion int          `json:"schema_version"`
	Domain        string       `json:"domain"`
	URL           string       `json:"url"`
	Probator      probe.Result `json:"probator"`
}

type target struct {
	domain   string
	hostname string
}

type jobResult struct {
	record outputRecord
	err    error
}

type logEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason"`
}

func Run(ctx context.Context, input io.Reader, output io.Writer, cfg Config) error {
	if input == nil {
		return errors.New("input is nil")
	}

	if output == nil {
		return errors.New("output is nil")
	}

	if cfg.Workers == 0 {
		cfg.Workers = defaultWorkers
	}

	if cfg.Workers < 1 {
		return errors.New("workers must be greater than zero")
	}

	p, err := probe.New(cfg.Probe)
	if err != nil {
		return fmt.Errorf("initialize prober: %w", err)
	}

	logger, err := logging.New(cfg.LogPath, cfg.Silent)
	if err != nil {
		return err
	}

	runErr := run(ctx, input, output, cfg, p)

	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		entry := logEntry{
			Timestamp: time.Now().UTC(),
			Reason:    runErr.Error(),
		}

		if logErr := logger.Write(entry); logErr != nil {
			runErr = errors.Join(runErr, logErr)
		}
	}

	closeErr := logger.Close()

	if runErr != nil {
		return runErr
	}

	if closeErr != nil {
		return closeErr
	}

	return nil
}

func run(
	ctx context.Context,
	input io.Reader,
	output io.Writer,
	cfg Config,
	p prober,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	targets, err := readInventory(ctx, input)
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	jobs := make(chan target)
	results := make(chan jobResult, cfg.Workers)

	var workers sync.WaitGroup
	workers.Add(cfg.Workers)

	for range cfg.Workers {
		go func() {
			defer workers.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}

				result, probeErr := p.Probe(ctx, job.hostname)

				if probeErr != nil {
					select {
					case results <- jobResult{err: fmt.Errorf("probe %s: %w", job.hostname, probeErr)}:
					case <-ctx.Done():
					}

					return
				}

				record := outputRecord{
					SchemaVersion: inputSchemaVersion,
					Domain:        job.domain,
					URL:           job.hostname,
					Probator:      result,
				}

				select {
				case results <- jobResult{record: record}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, item := range targets {
			select {
			case jobs <- item:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	encoder := json.NewEncoder(output)
	var runErr error

	for item := range results {
		if item.err != nil {
			if runErr == nil {
				runErr = item.err
				cancel()
			}

			continue
		}

		if runErr != nil {
			continue
		}

		if err := encoder.Encode(item.record); err != nil {
			runErr = fmt.Errorf("write JSONL output: %w", err)
			cancel()
		}
	}

	if runErr != nil {
		return runErr
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return nil
}

func readInventory(ctx context.Context, input io.Reader) ([]target, error) {
	reader := bufio.NewReader(input)

	readDone := make(chan struct{})
	closeDone := make(chan struct{})

	if closer, ok := input.(io.Closer); ok {
		go func() {
			defer close(closeDone)
			select {
			case <-ctx.Done():
				_ = closer.Close()
			case <-readDone:
			}
		}()

		defer func() {
			close(readDone)
			<-closeDone
		}()
	}

	unique := make(map[string]int)
	targets := make([]target, 0)

	var lineNumber int
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		line, readErr := reader.ReadString('\n')

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if len(line) > 0 {
			lineNumber++
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")

			if strings.TrimSpace(line) != "" {
				var record inputRecord

				if err := json.Unmarshal([]byte(line), &record); err != nil {
					return nil, fmt.Errorf("input line %d: decode JSON: %w", lineNumber, err)
				}

				if record.SchemaVersion != inputSchemaVersion {
					return nil, fmt.Errorf("input line %d: unsupported schema_version %d (supported: %d)", lineNumber, record.SchemaVersion, inputSchemaVersion)
				}

				if strings.TrimSpace(record.Domain) == "" {
					return nil, fmt.Errorf("input line %d: missing domain", lineNumber)
				}

				if record.URL == "" {
					return nil, fmt.Errorf("input line %d: missing hostname", lineNumber)
				}

				hostname := normalizeName(record.URL)
				domain := normalizeName(record.Domain)

				if index, exists := unique[hostname]; exists {
					if normalizeName(targets[index].domain) != domain {
						return nil, fmt.Errorf(
							"input line %d: hostname %q has conflicting domains %q and %q",
							lineNumber,
							hostname,
							targets[index].domain,
							record.Domain,
						)
					}
				} else {
					unique[hostname] = len(targets)
					targets = append(targets, target{domain: record.Domain, hostname: hostname})
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}

			return nil, fmt.Errorf("read input: %w", readErr)
		}
	}

	return targets, nil
}

func normalizeName(value string) string {
	return strings.TrimSuffix(strings.ToLower(value), ".")
}
