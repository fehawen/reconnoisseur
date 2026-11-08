package app

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/fehawen/reconnoisseur/internal/shared/aggregate"
	"github.com/fehawen/reconnoisseur/internal/shared/cli"
	"github.com/fehawen/reconnoisseur/internal/shared/input"
	"github.com/fehawen/reconnoisseur/internal/shared/logging"
	"github.com/fehawen/reconnoisseur/internal/shared/model"
	"github.com/fehawen/reconnoisseur/internal/shared/normalize"
	"github.com/fehawen/reconnoisseur/internal/shared/runner"
)

func Run(
	name string,
	providerList []runner.Provider,
	normalizeURL func(string, string) (string, error),
	prepareResults func(string, string, []model.Result) ([]model.Result, error),
) error {
	opts, err := cli.ParseArgs(name, os.Args[1:])
	if err != nil {
		return err
	}

	domains, err := input.LoadDomains(opts, os.Stdin)
	if err != nil {
		return err
	}

	if len(domains) == 0 {
		return errors.New("no domains provided")
	}

	for i, value := range domains {
		domains[i], err = normalize.Domain(value, "")
		if err != nil {
			return fmt.Errorf("invalid input domain %q: %w", value, err)
		}
	}

	logger, err := logging.New(opts.LogPath, opts.Silent)
	if err != nil {
		return err
	}

	aggregator := aggregate.New(normalizeURL)

	r := runner.New(providerList, aggregator, logger, prepareResults)

	var runErr error

	for _, domain := range domains {
		if err := r.RunDomain(context.Background(), domain); err != nil {
			runErr = fmt.Errorf("process domain %q: %w", domain, err)
			break
		}
	}

	closeErr := logger.Close()

	if runErr != nil {
		return runErr
	}

	if closeErr != nil {
		return closeErr
	}

	if err := aggregator.WriteJSONL(os.Stdout); err != nil {
		return err
	}

	return nil
}
