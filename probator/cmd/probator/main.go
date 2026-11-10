package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fehawen/reconnoisseur/probator/internal/app"
)

func main() {
	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintf(os.Stderr, "probator: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := app.DefaultConfig()
	probeCfg := cfg.Probe

	flag.IntVar(
		&cfg.Workers,
		"workers",
		cfg.Workers,
		"concurrent hostnames",
	)

	flag.DurationVar(
		&probeCfg.DNSTimeout,
		"dns-timeout",
		probeCfg.DNSTimeout,
		"DNS lookup timeout",
	)

	flag.DurationVar(
		&probeCfg.RequestTimeout,
		"timeout",
		probeCfg.RequestTimeout,
		"HTTP request timeout",
	)

	flag.IntVar(
		&probeCfg.MaxRedirects,
		"max-redirects",
		probeCfg.MaxRedirects,
		"maximum redirects per request",
	)

	flag.Int64Var(
		&probeCfg.MaxBodySize,
		"max-body-size",
		probeCfg.MaxBodySize,
		"maximum response body bytes read",
	)

	flag.StringVar(
		&probeCfg.UserAgent,
		"user-agent",
		probeCfg.UserAgent,
		"HTTP User-Agent",
	)

	flag.StringVar(
		&cfg.LogPath,
		"log",
		cfg.LogPath,
		"log file path",
	)

	flag.BoolVar(
		&cfg.Silent,
		"silent",
		cfg.Silent,
		"disable application logging",
	)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: probator [options] < input.jsonl\n\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "probator: positional arguments not supported, provide JSONL on stdin")
		os.Exit(2)
	}

	cfg.Probe = probeCfg

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return app.Run(ctx, os.Stdin, os.Stdout, cfg)
}
