package normalize

import (
	"fmt"
	"strings"
)

func Domain(value, _ string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))

	if err := ValidateDNSName(value); err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", value, err)
	}

	return value, nil
}
