package normalize

import (
	"fmt"
	"strings"
)

func ValidateDNSName(value string) error {
	if value == "" || len(value) > 253 {
		return fmt.Errorf("DNS name length is invalid")
	}

	if strings.ContainsAny(value, " /:@?#[]\\\\") {
		return fmt.Errorf("DNS name contains invalid characters")
	}

	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("DNS label length is invalid")
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("DNS label has an invalid hyphen position")
		}

		for _, c := range label {
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				continue
			}

			return fmt.Errorf("DNS label contains an invalid character")
		}
	}

	return nil
}
