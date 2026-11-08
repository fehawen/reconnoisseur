package provider

type Metadata struct {
	ProviderName   string
	APIKeyEnvName  string
	APIKeyRequired bool
}

func (m Metadata) Name() string {
	return m.ProviderName
}

func (m Metadata) APIKeyEnv() string {
	return m.APIKeyEnvName
}

func (m Metadata) RequiresAPIKey() bool {
	return m.APIKeyRequired
}
