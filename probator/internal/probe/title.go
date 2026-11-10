package probe

import (
	"html"
	"io"
	"mime"
	"regexp"
	"strings"
)

var (
	titlePattern = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)
	tagPattern   = regexp.MustCompile(`(?s)<[^>]*>`)
)

func normalizedContentType(value string) string {
	if value == "" {
		return ""
	}

	mediaType, _, err := mime.ParseMediaType(value)

	if err != nil {
		return ""
	}

	return strings.ToLower(mediaType)
}

func isHTMLContentType(contentType string) bool {
	return contentType == "text/html" || contentType == "application/xhtml+xml"
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(reader, maxBytes))
}

func extractHTMLTitle(body []byte) string {
	match := titlePattern.FindSubmatch(body)

	if len(match) != 2 {
		return ""
	}

	text := tagPattern.ReplaceAllString(string(match[1]), " ")
	decoded := html.UnescapeString(text)

	return strings.Join(strings.Fields(decoded), " ")
}
