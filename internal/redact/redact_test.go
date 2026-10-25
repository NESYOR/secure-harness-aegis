package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsCommonSecrets(t *testing.T) {
	input := strings.Join([]string{
		"alice@example.com",
		"123-45-6789",
		"10.0.0.5",
		"Bearer abc.def.ghi",
		"token ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"AKIAABCDEFGHIJKLMNOP",
		"sk-abcdefghijklmnopqrstuvwxyz",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
	}, " | ")

	out := Text(input)
	for _, marker := range []string{
		"[REDACTED_EMAIL]",
		"[REDACTED_SSN]",
		"[REDACTED_INTERNAL_IP]",
		"[REDACTED_GITHUB_TOKEN]",
		"[REDACTED_AWS_KEY]",
		"[REDACTED_API_KEY]",
		"[REDACTED_JWT]",
		"[REDACTED_PRIVATE_KEY]",
	} {
		if !strings.Contains(out, marker) {
			t.Errorf("missing %s in %q", marker, out)
		}
	}
	for _, secret := range []string{"alice@example.com", "123-45-6789", "10.0.0.5", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "AKIAABCDEFGHIJKLMNOP"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q survived redaction: %q", secret, out)
		}
	}
}

func TestMapRedactsSensitiveKeys(t *testing.T) {
	in := map[string]any{
		"query":    "SELECT * FROM users",
		"password": "hunter2",
		"nested": map[string]any{
			"api_key": "abc123",
			"email":   "bob@example.com",
		},
	}
	out, ok := Map(in).(map[string]any)
	if !ok {
		t.Fatal("Map did not return a map")
	}
	if out["password"] != "[REDACTED]" {
		t.Fatalf("password = %v", out["password"])
	}
	nested := out["nested"].(map[string]any)
	if nested["api_key"] != "[REDACTED]" {
		t.Fatalf("api_key = %v", nested["api_key"])
	}
	if nested["email"] != "[REDACTED_EMAIL]" {
		t.Fatalf("email = %v", nested["email"])
	}
}

func TestSecretPlaceholders(t *testing.T) {
	vault := map[string]string{"GITHUB_TOKEN": "ghp_real"}
	out, missing := ReplaceSecrets("token {{SECRET:GITHUB_TOKEN}} db {{SECRET:DB_PASSWORD}}", vault)
	if len(missing) != 1 || missing[0] != "DB_PASSWORD" {
		t.Fatalf("missing = %v", missing)
	}
	if !strings.Contains(out, "ghp_real") || !strings.Contains(out, "{{SECRET:DB_PASSWORD}}") {
		t.Fatalf("out = %q", out)
	}

	names := SecretNames("{{SECRET:A}} {{SECRET:B}}")
	if len(names) != 2 || names[0] != "A" || names[1] != "B" {
		t.Fatalf("names = %v", names)
	}
}
