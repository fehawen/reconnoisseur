package httpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/fehawen/reconnoisseur/internal/shared/model"
)

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
	req.Header.Set("User-Agent", "reconnoisseur/0.1.0")

	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := client.Do(req)
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
