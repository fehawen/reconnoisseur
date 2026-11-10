package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/fehawen/reconnoisseur/internal/shared/model"
)

const UserAgent = "reconnoisseur/1.0"
const maxResponseBytes = 32 << 20

func Get(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	headers http.Header,
) ([]byte, error) {
	if client == nil {
		return nil, &model.ProviderError{Reason: "invalid_client"}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "invalid_request",
			Err:    err,
		}
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	requestClient := *client
	originalCheckRedirect := client.CheckRedirect
	requestClient.CheckRedirect = func(redirect *http.Request, via []*http.Request) error {
		if len(via) > 0 && !sameOrigin(via[0].URL, redirect.URL) {
			if requestHasCredentials(via[0]) {
				return http.ErrUseLastResponse
			}

			stripCredentialHeaders(redirect)
		}

		if originalCheckRedirect != nil {
			return originalCheckRedirect(redirect, via)
		}

		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}

		return nil
	}

	resp, err := requestClient.Do(req)
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "request_failed",
			Err:    err,
		}
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &model.ProviderError{
			Reason: fmt.Sprintf("http_status_%d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, &model.ProviderError{
			Reason: "response_read_failed",
			Err:    err,
		}
	}

	if len(body) > maxResponseBytes {
		return nil, &model.ProviderError{
			Reason: "response_too_large",
		}
	}

	return body, nil
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}

	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}

	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}

	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}

	return ""
}

func requestHasCredentials(req *http.Request) bool {
	if req == nil {
		return false
	}

	if req.URL != nil && req.URL.User != nil {
		return true
	}

	for name := range req.Header {
		if isCredentialHeader(name) {
			return true
		}
	}

	if req.URL != nil {
		for name := range req.URL.Query() {
			switch strings.ToLower(name) {
			case "key", "api_key", "apikey", "access_token", "token":
				return true
			}
		}
	}

	return false
}

func isCredentialHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "api-key", "x-api-key", "x-apikey", "x-otx-api-key", "x-shodan-api-key":
		return true
	default:
		return false
	}
}

func stripCredentialHeaders(req *http.Request) {
	for name := range req.Header {
		if isCredentialHeader(name) {
			req.Header.Del(name)
		}
	}
}
