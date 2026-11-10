package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/fehawen/reconnoisseur/internal/shared/httpclient"
)

const (
	defaultDNSTimeout     = 5 * time.Second
	defaultRequestTimeout = 10 * time.Second
	defaultMaxRedirects   = 5
	defaultMaxBodySize    = int64(1 << 20)
	defaultUserAgent      = httpclient.UserAgent
)

type State string

const (
	StateSuccess State = "success"
	StateError   State = "error"
	StateSkipped State = "skipped"
)

type Config struct {
	DNSTimeout     time.Duration
	RequestTimeout time.Duration
	MaxRedirects   int
	MaxBodySize    int64
	UserAgent      string
}

func DefaultConfig() Config {
	return Config{
		DNSTimeout:     defaultDNSTimeout,
		RequestTimeout: defaultRequestTimeout,
		MaxRedirects:   defaultMaxRedirects,
		MaxBodySize:    defaultMaxBodySize,
		UserAgent:      defaultUserAgent,
	}
}

type DNSResult struct {
	State     State    `json:"state"`
	Addresses []string `json:"addresses,omitempty"`
	Error     string   `json:"error,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type HTTPResult struct {
	State       State  `json:"state"`
	StatusCode  int    `json:"status_code,omitempty"`
	FinalURL    string `json:"final_url,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	Error       string `json:"error,omitempty"`
	Reason      string `json:"reason,omitempty"`

	TLSVerified *bool `json:"tls_verified,omitempty"`
}

type Result struct {
	DNS   DNSResult  `json:"dns"`
	HTTP  HTTPResult `json:"http"`
	HTTPS HTTPResult `json:"https"`
}

type Prober struct {
	config    Config
	resolver  ipResolver
	tlsConfig *tls.Config
}

func New(cfg Config) (*Prober, error) {
	return newProber(cfg, net.DefaultResolver)
}

func newProber(cfg Config, resolver ipResolver) (*Prober, error) {
	return newProberWithTLS(cfg, resolver, nil)
}

func newProberWithTLS(cfg Config, resolver ipResolver, tlsConfig *tls.Config) (*Prober, error) {
	if resolver == nil {
		return nil, errors.New("DNS resolver is nil")
	}

	if cfg.DNSTimeout == 0 {
		cfg.DNSTimeout = defaultDNSTimeout
	}

	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = defaultRequestTimeout
	}

	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = defaultMaxBodySize
	}

	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}

	if cfg.DNSTimeout < 0 {
		return nil, errors.New("DNS timeout must be positive")
	}

	if cfg.RequestTimeout < 0 {
		return nil, errors.New("request timeout must be positive")
	}

	if cfg.MaxRedirects < 0 {
		return nil, errors.New("maximum redirects cannot be negative")
	}

	if cfg.MaxBodySize < 0 {
		return nil, errors.New("maximum response body size cannot be negative")
	}

	if strings.TrimSpace(cfg.UserAgent) == "" {
		return nil, errors.New("User-Agent cannot be empty")
	}

	return &Prober{
		config:    cfg,
		resolver:  resolver,
		tlsConfig: tlsConfig,
	}, nil
}

func (p *Prober) Probe(ctx context.Context, hostname string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	hostname = normalizeHostname(hostname)
	if strings.HasPrefix(hostname, "*.") {
		return skippedResult("wildcard_hostname"), nil
	}

	if !validHostname(hostname) {
		return skippedResult("invalid_hostname"), nil
	}

	addresses, err := p.resolveHostname(ctx, hostname)
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}

	if err != nil || len(addresses) == 0 {
		if err == nil {
			err = errors.New("resolver returned no addresses")
		}

		return Result{
			DNS:   DNSResult{State: StateError, Error: classifyDNSError(err)},
			HTTP:  HTTPResult{State: StateSkipped, Reason: "dns_error"},
			HTTPS: HTTPResult{State: StateSkipped, Reason: "dns_error"},
		}, nil
	}

	result := Result{
		DNS: DNSResult{State: StateSuccess, Addresses: ipAddrStrings(addresses)},
	}

	client, cleanup, err := newHTTPClient(transportConfig{
		initialHostname:  hostname,
		initialAddresses: addresses,
		resolver:         p.resolver,
		dnsTimeout:       p.config.DNSTimeout,
		maxRedirects:     p.config.MaxRedirects,
		dialTimeout:      p.config.RequestTimeout,
		tlsConfig:        p.tlsConfig,
	})
	if err != nil {
		return Result{}, err
	}

	defer cleanup()

	type outcome struct {
		scheme string
		result HTTPResult
		err    error
	}

	probeCtx, stop := context.WithCancel(ctx)
	defer stop()

	outcomes := make(chan outcome, 2)

	for _, scheme := range []string{"http", "https"} {
		go func() {
			r, probeErr := p.probeURL(probeCtx, client, hostname, scheme)
			outcomes <- outcome{scheme: scheme, result: r, err: probeErr}
		}()
	}

	var probeErr error

	ctxDone := ctx.Done()

	for range 2 {
		select {
		case <-ctxDone:
			if probeErr == nil {
				probeErr = ctx.Err()
				stop()
			}

			ctxDone = nil
		case outcome := <-outcomes:
			if outcome.err != nil {
				if probeErr == nil {
					probeErr = outcome.err
					stop()
				}

				continue
			}

			if outcome.scheme == "https" {
				result.HTTPS = outcome.result
			} else {
				result.HTTP = outcome.result
			}
		}
	}

	if probeErr != nil {
		return Result{}, probeErr
	}

	return result, nil
}

func (p *Prober) probeURL(parent context.Context, client *http.Client, hostname, scheme string) (HTTPResult, error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, p.config.RequestTimeout)

	defer cancel()

	target := &url.URL{Scheme: scheme, Host: hostname, Path: "/"}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return HTTPResult{}, err
	}

	req.Header.Set("User-Agent", p.config.UserAgent)
	req.Header.Set("Accept", "*/*")

	return p.probeRequest(parent, client, req, scheme, started)
}

func (p *Prober) probeRequest(parent context.Context, client *http.Client, req *http.Request, scheme string, started time.Time) (HTTPResult, error) {
	resp, err := client.Do(req)
	if err != nil {
		if parent.Err() != nil {
			return HTTPResult{}, parent.Err()
		}

		result := HTTPResult{
			State:      StateError,
			Error:      classifyHTTPError(err),
			DurationMS: time.Since(started).Milliseconds(),
		}

		if scheme == "https" && result.Error == "tls_error" {
			verified := false
			result.TLSVerified = &verified
		}

		return result, nil
	}

	defer resp.Body.Close()

	finalURL := req.URL

	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL
	}

	result := HTTPResult{
		State:       StateSuccess,
		StatusCode:  resp.StatusCode,
		FinalURL:    finalURL.String(),
		ContentType: normalizedContentType(resp.Header.Get("Content-Type")),
	}

	if scheme == "https" && resp.TLS != nil {
		verified := true
		result.TLSVerified = &verified
	}

	if isHTMLContentType(result.ContentType) {
		body, readErr := readBounded(resp.Body, p.config.MaxBodySize)
		if readErr != nil {
			if parent.Err() != nil {
				return HTTPResult{}, parent.Err()
			}

			if req.Context().Err() != nil {
				result.State = StateError
				result.Error = "timeout"
			} else {
				result.State = StateError
				result.Error = "invalid_response"
			}
		} else {
			result.Title = extractHTMLTitle(body)
		}
	}

	result.DurationMS = time.Since(started).Milliseconds()

	return result, nil
}

func skippedResult(reason string) Result {
	return Result{
		DNS:   DNSResult{State: StateSkipped, Reason: reason},
		HTTP:  HTTPResult{State: StateSkipped, Reason: reason},
		HTTPS: HTTPResult{State: StateSkipped, Reason: reason},
	}
}

func classifyHTTPError(err error) string {
	var dnsErr *dnsResolutionError

	if errors.As(err, &dnsErr) {
		return "dns_error"
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}

	var netErr net.Error

	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}

	var certErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError

	if errors.As(err, &certErr) || errors.As(err, &recordErr) || errors.As(err, &alertErr) {
		return "tls_error"
	}

	if strings.Contains(strings.ToLower(err.Error()), "malformed http response") {
		return "invalid_response"
	}

	if strings.Contains(strings.ToLower(err.Error()), "tls:") {
		return "tls_error"
	}

	return "connection_error"
}
