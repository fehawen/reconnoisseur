package normalize

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Canonicalize an absolute HTTP(S) URL without discarding its query or
// fragment. Fragments are retained because they can represent client-side routes.
func canonicalizeURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("URL is empty")
	}

	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}

	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("URL has no host")
	}

	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return "", fmt.Errorf("URL has no hostname")
	}

	if err := ValidateDNSName(host); err != nil {
		return "", fmt.Errorf("URL has an invalid hostname")
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("URL has an invalid port")
		}
	}

	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}

	if strings.Contains(host, ":") {
		u.Host = net.JoinHostPort(host, port)
		if port == "" {
			u.Host = "[" + host + "]"
		}
	} else if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}

	if u.Path == "" {
		u.Path = "/"
	}

	return u.String(), nil
}

func inScope(domain, hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

func URL(value, domain string) (string, error) {
	normalized, err := canonicalizeURL(value)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(normalized)
	if err != nil || !inScope(domain, u.Hostname()) {
		return "", fmt.Errorf("URL %q not in scope", normalized)
	}

	return normalized, nil
}
