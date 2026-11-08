package input

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fehawen/reconnoisseur/internal/shared/cli"
)

func LoadDomains(opts cli.Options, stdin io.Reader) ([]string, error) {
	if opts.File != "" {
		file, err := os.Open(opts.File)
		if err != nil {
			return nil, fmt.Errorf("open domain file: %w", err)
		}

		defer file.Close()

		return readDomains(file)
	}

	if len(opts.Domains) > 0 {
		return opts.Domains, nil
	}

	return readDomains(stdin)
}

func readDomains(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)

	// Domain lists should have short lines, but allow room for malformed input
	// to be handled later without Scanner's small default limit.
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	var domains []string

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		domains = append(domains, domain)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read domains: %w", err)
	}

	return domains, nil
}
