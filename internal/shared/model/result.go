package model

const SchemaVersion = 1

type Result struct {
	SchemaVersion int        `json:"schema_version"`
	Domain        string     `json:"domain"`
	URL           string     `json:"url,omitempty"`
	Evidence      []Evidence `json:"evidence"`
}
