package model

type ProviderStatus string

const (
	StatusSuccess ProviderStatus = "success"
	StatusEmpty   ProviderStatus = "empty"
	StatusError   ProviderStatus = "error"
	StatusSkipped ProviderStatus = "skipped"
)

type ProviderError struct {
	Reason string
	Err    error
}

func (e *ProviderError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}

	return e.Reason
}

func (e *ProviderError) Unwrap() error {
	return e.Err
}
