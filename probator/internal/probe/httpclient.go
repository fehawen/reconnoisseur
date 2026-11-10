package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultDialTimeout  = 5 * time.Second
	defaultTLSHandshake = 5 * time.Second
	defaultIdleTimeout  = 30 * time.Second
	defaultMaxIdleConns = 8
	defaultMaxConnsHost = 2
)

type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type transportConfig struct {
	initialHostname  string
	initialAddresses []net.IPAddr
	resolver         ipResolver
	dnsTimeout       time.Duration
	maxRedirects     int
	dialTimeout      time.Duration
	tlsConfig        *tls.Config
}

type dnsResolutionError struct {
	host string
	err  error
}

func (e *dnsResolutionError) Error() string {
	return fmt.Sprintf("resolve %q: %v", e.host, e.err)
}

func (e *dnsResolutionError) Unwrap() error {
	return e.err
}

func newHTTPClient(cfg transportConfig) (*http.Client, func(), error) {
	if cfg.initialHostname == "" {
		return nil, nil, errors.New("initial hostname is empty")
	}

	if len(cfg.initialAddresses) == 0 {
		return nil, nil, errors.New("initial DNS address list is empty")
	}

	if cfg.resolver == nil {
		cfg.resolver = net.DefaultResolver
	}

	if cfg.dnsTimeout <= 0 {
		cfg.dnsTimeout = defaultDNSTimeout
	}

	if cfg.maxRedirects < 0 {
		return nil, nil, errors.New("maximum redirects cannot be negative")
	}

	if cfg.dialTimeout <= 0 {
		cfg.dialTimeout = defaultDialTimeout
	}

	resolver := &probeResolver{
		resolver: cfg.resolver,
		timeout:  cfg.dnsTimeout,
		cache:    make(map[string]*resolutionEntry),
	}

	resolver.store(normalizeDNSName(cfg.initialHostname), cloneIPAddrs(cfg.initialAddresses), nil)

	dialer := &pinnedDialer{
		resolver: resolver,
		dialer:   &net.Dialer{Timeout: cfg.dialTimeout, KeepAlive: 30 * time.Second},
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxConnsHost,
		MaxConnsPerHost:       defaultMaxConnsHost,
		IdleConnTimeout:       defaultIdleTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshake,
		ExpectContinueTimeout: time.Second,
	}

	if cfg.tlsConfig != nil {
		tlsConfig := cfg.tlsConfig.Clone()

		tlsConfig.ServerName = ""
		tlsConfig.InsecureSkipVerify = false

		transport.TLSClientConfig = tlsConfig
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > cfg.maxRedirects {
				return http.ErrUseLastResponse
			}

			if !redirectURLAllowed(req.URL) {
				return http.ErrUseLastResponse
			}

			stripSensitiveHeaders(req)

			return nil
		},
		Jar: nil,
	}

	return client, transport.CloseIdleConnections, nil
}

func stripSensitiveHeaders(req *http.Request) {
	req.Header.Del("Authorization")
	req.Header.Del("Cookie")
	req.Header.Del("Proxy-Authorization")
}

type resolutionEntry struct {
	ready     chan struct{}
	addresses []net.IPAddr
	err       error
}

type probeResolver struct {
	resolver ipResolver
	timeout  time.Duration

	mu    sync.Mutex
	cache map[string]*resolutionEntry
}

func (r *probeResolver) store(host string, addresses []net.IPAddr, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := &resolutionEntry{ready: make(chan struct{}), addresses: cloneIPAddrs(addresses), err: err}

	close(entry.ready)

	r.cache[host] = entry
}

func (r *probeResolver) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = normalizeDNSName(host)
	if host == "" {
		return nil, &dnsResolutionError{host: host, err: errors.New("empty hostname")}
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		ip := net.ParseIP(addr.WithZone("").String())
		if ip == nil {
			return nil, &dnsResolutionError{host: host, err: errors.New("invalid IP address")}
		}

		return []net.IPAddr{{IP: ip, Zone: addr.Zone()}}, nil
	}

	r.mu.Lock()

	if entry, ok := r.cache[host]; ok {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-entry.ready:
			if entry.err != nil {
				return nil, &dnsResolutionError{host: host, err: entry.err}
			}

			return cloneIPAddrs(entry.addresses), nil
		}
	}

	entry := &resolutionEntry{ready: make(chan struct{})}

	r.cache[host] = entry
	r.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, r.timeout)
	addresses, err := r.resolver.LookupIPAddr(lookupCtx, host)

	cancel()

	addresses = uniqueIPAddrs(addresses)
	if err == nil && len(addresses) == 0 {
		err = errors.New("resolver returned no addresses")
	}

	r.mu.Lock()

	entry.addresses = cloneIPAddrs(addresses)
	entry.err = err

	close(entry.ready)

	r.mu.Unlock()

	if err != nil {
		return nil, &dnsResolutionError{host: host, err: err}
	}

	return cloneIPAddrs(addresses), nil
}

type pinnedDialer struct {
	resolver *probeResolver
	dialer   *net.Dialer
}

func (d *pinnedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split dial address %q: %w", address, err)
	}

	addresses, err := d.resolver.lookup(ctx, host)
	if err != nil {
		return nil, err
	}

	var attempts []error
	for _, addr := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if network == "tcp4" && addr.IP.To4() == nil {
			continue
		}

		if network == "tcp6" && addr.IP.To4() != nil {
			continue
		}

		target := net.JoinHostPort(addr.String(), port)

		conn, dialErr := d.dialer.DialContext(ctx, network, target)
		if dialErr == nil {
			return conn, nil
		}

		attempts = append(attempts, fmt.Errorf("%s: %w", target, dialErr))
	}

	if len(attempts) == 0 {
		return nil, fmt.Errorf("no addresses available for network %q and host %q", network, host)
	}

	return nil, fmt.Errorf("all addresses for %q failed: %w", host, errors.Join(attempts...))
}

func normalizeDNSName(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func cloneIPAddrs(addresses []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, len(addresses))

	for i, addr := range addresses {
		out[i] = net.IPAddr{IP: append(net.IP(nil), addr.IP...), Zone: addr.Zone}
	}

	return out
}

func uniqueIPAddrs(addresses []net.IPAddr) []net.IPAddr {
	seen := make(map[string]struct{}, len(addresses))
	out := make([]net.IPAddr, 0, len(addresses))

	for _, addr := range addresses {
		key := addr.String()

		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		out = append(out, net.IPAddr{IP: append(net.IP(nil), addr.IP...), Zone: addr.Zone})
	}

	return out
}

func redirectURLAllowed(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil
}
