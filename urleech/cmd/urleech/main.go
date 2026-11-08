package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/fehawen/reconnoisseur/urleech/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}

		fmt.Fprintf(os.Stderr, "urleech: %v\n", err)
		os.Exit(1)
	}
}
