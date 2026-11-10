package probe

import (
	"context"
	"errors"
	"net"
	"strings"
)

func normalizeHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(hostname), ".")
}

func validHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 || strings.TrimSpace(hostname) != hostname {
		return false
	}

	if net.ParseIP(hostname) != nil {
		return false
	}

	for label := range strings.SplitSeq(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}

	return true
}

func (p *Prober) resolveHostname(parent context.Context, hostname string) ([]net.IPAddr, error) {
	ctx, cancel := context.WithTimeout(parent, p.config.DNSTimeout)

	defer cancel()

	addresses, err := p.resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, err
	}

	addresses = uniqueIPAddrs(addresses)

	if len(addresses) == 0 {
		return nil, errors.New("resolver returned no addresses")
	}

	return addresses, nil
}

func ipAddrStrings(addresses []net.IPAddr) []string {
	out := make([]string, 0, len(addresses))

	for _, address := range addresses {
		out = append(out, address.String())
	}

	return out
}

func classifyDNSError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}

	var dnsErr *net.DNSError

	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "no_such_host"
		}

		if dnsErr.IsTimeout {
			return "timeout"
		}
	}

	return "resolver_error"
}
