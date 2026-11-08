package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

type Options struct {
	File    string
	LogPath string
	Silent  bool
	Domains []string
}

func ParseArgs(app string, args []string) (Options, error) {
	var opts Options

	fs := flag.NewFlagSet(app, flag.ContinueOnError)

	fs.SetOutput(os.Stderr)

	fs.StringVar(&opts.File, "file", "", "read domains from a file")
	fs.StringVar(&opts.LogPath, "log", "./"+app+".log", "log file path")
	fs.BoolVar(&opts.Silent, "silent", false, "disable application logging")

	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: "+app+" [options] [domain ...]")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return Options{}, err
	}

	opts.Domains = fs.Args()

	if opts.File != "" && len(opts.Domains) > 0 {
		return Options{}, errors.New("cannot combine -file with positional domains")
	}

	for i := range opts.Domains {
		opts.Domains[i] = strings.TrimSpace(opts.Domains[i])
		if opts.Domains[i] == "" {
			return Options{}, errors.New("empty positional domain")
		}
	}

	return opts, nil
}
