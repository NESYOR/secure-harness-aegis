// Package redact removes common credentials and personal data from values
// before they are written to logs or the audit ledger.
package redact

import (
	"encoding/json"
	"regexp"
	"strings"
)

type rule struct {
	re   *regexp.Regexp
	repl string
}

var rules = []rule{
	// Private keys first: they span multiple lines and may contain other
	// patterns that would otherwise be partially redacted.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), "[REDACTED_PRIVATE_KEY]"},
	{regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*`), "Bearer [REDACTED_TOKEN]"},
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), "[REDACTED_GITHUB_TOKEN]"},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), "[REDACTED_GITHUB_TOKEN]"},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`), "[REDACTED_SLACK_TOKEN]"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "[REDACTED_AWS_KEY]"},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`), "[REDACTED_API_KEY]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`), "[REDACTED_JWT]"},
	{regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`), "[REDACTED_EMAIL]"},
	{regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "[REDACTED_SSN]"},
	{regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b`), "[REDACTED_INTERNAL_IP]"},
}

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key)`)

// Text redacts sensitive patterns from a string.
func Text(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// JSON redacts a value and returns its JSON encoding. The result remains valid
// JSON because every replacement is a plain token without quotes or
// backslashes.
func JSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"unserializable"}`
	}
	return Text(string(b))
}

// Map returns a deep copy of a JSON-like value with sensitive keys and string
// patterns redacted. It is used before echoing arguments to logs.
func Map(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if sensitiveKey.MatchString(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = Map(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = Map(val)
		}
		return out
	case string:
		return Text(x)
	default:
		return v
	}
}

// Placeholder finds secret placeholders of the form {{SECRET:NAME}}.
var Placeholder = regexp.MustCompile(`\{\{SECRET:([A-Za-z0-9_]+)\}\}`)

// SecretNames lists secret names referenced in a string.
func SecretNames(s string) []string {
	matches := Placeholder.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// ReplaceSecrets substitutes placeholders using the provided vault. It returns
// an error string listing any placeholder that has no configured secret.
func ReplaceSecrets(s string, vault map[string]string) (string, []string) {
	var missing []string
	out := Placeholder.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(m, "{{SECRET:"), "}}")
		if v, ok := vault[name]; ok && v != "" {
			return v
		}
		missing = append(missing, name)
		return m
	})
	return out, missing
}
