package intercept

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"
)

func getDomains() ([]string, error) {
	domains := os.Args[1:]
	if len(domains) == 0 {
		return nil, errors.New("you need to specify a list of domains to intercept as arguments to the command")
	}

	for _, domain := range domains {
		if !isValidDomain(domain) {
			return nil, fmt.Errorf("invalid domain: %v", domain)
		}
	}

	return domains, nil
}

func isValidDomain(domain string) bool {
	// Length check: Domain name must not be more than 253 characters
	if len(domain) > 253 {
		return false
	}

	// Split the domain into labels (parts between dots)
	labels := strings.Split(domain, ".")

	// There must be at least two labels (e.g., "example.com")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		// Length check for each label
		if len(label) < 1 || len(label) > 63 {
			return false
		}

		// Each label must only contain alphanumeric characters or hyphens
		for i, r := range label {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
				return false
			}

			// Labels can't start or end with a hyphen
			if (i == 0 || i == len(label)-1) && r == '-' {
				return false
			}
		}
	}

	// If all checks passed, it's a valid domain name
	return true
}
