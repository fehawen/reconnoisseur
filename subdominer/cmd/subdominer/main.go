package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/fehawen/reconnoisseur/subdominer/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintf(os.Stderr, "subdominer: %v\n", err)
		os.Exit(1)
	}
}
