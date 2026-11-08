package provider

import "time"

func ParseTimestamp(value string) *time.Time {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"20060102150405",
		"2006010215",
		"20060102",
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05-07",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05.999999999",
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, value)
		if err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}
