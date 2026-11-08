package normalize

import (
	"fmt"
	"strings"
)

func Hostname(domain, hostname string) (normalized string, wildcard bool, err error) {
	domain, err = Domain(domain, "")
	if err != nil {
		return "", false, err
	}

	hostname = strings.TrimSpace(hostname)
	hostname = strings.TrimSuffix(hostname, ".")
	hostname = strings.ToLower(hostname)

	if strings.HasPrefix(hostname, "*.") {
		wildcard = true
		hostname = strings.TrimPrefix(hostname, "*.")
	}

	if err := ValidateDNSName(hostname); err != nil {
		return "", false, fmt.Errorf("invalid hostname %q: %w", hostname, err)
	}

	if hostname != domain && !strings.HasSuffix(hostname, "."+domain) {
		return "", false, fmt.Errorf(
			"hostname %q does not belong to domain %q",
			hostname,
			domain,
		)
	}

	if wildcard {
		return "*." + hostname, true, nil
	}

	return hostname, false, nil
}
