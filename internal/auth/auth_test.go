package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager([]string{"query_db", "execute_code"}, "0123456789abcdef")
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestMissingAndMalformedCredentialsFailClosed(t *testing.T) {
	m := testManager(t)

	for _, header := range []string{"", "Bearer ", "Basic abc", "Bearer not-a-jwt"} {
		if p, err := m.Authenticate(header); err == nil || p != nil {
			t.Fatalf("Authenticate(%q) = %+v, %v; want error", header, p, err)
		}
	}
}

func TestRootTokenRoundTrip(t *testing.T) {
	m := testManager(t)
	token, err := m.MintRoot("root-agent")
	if err != nil {
		t.Fatalf("MintRoot: %v", err)
	}

	p, err := m.Authenticate("Bearer " + token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject != "root-agent" || p.Type != TokenTypeAgent {
		t.Fatalf("principal = %+v", p)
	}
	if strings.Join(p.Scopes, ",") != "query_db,execute_code" {
		t.Fatalf("scopes = %v", p.Scopes)
	}
}

func TestDelegationIntersectsScopes(t *testing.T) {
	m := testManager(t)
	root, _ := m.MintRoot("root-agent")
	parent, err := m.Authenticate("Bearer " + root)
	if err != nil {
		t.Fatal(err)
	}

	child, granted, err := m.MintDelegation(parent, "child", []string{"query_db", "deploy_service"})
	if err != nil {
		t.Fatalf("MintDelegation: %v", err)
	}
	if strings.Join(granted, ",") != "query_db" {
		t.Fatalf("granted = %v", granted)
	}

	childPrincipal, err := m.Authenticate("Bearer " + child)
	if err != nil {
		t.Fatalf("Authenticate child: %v", err)
	}
	if childPrincipal.Depth != 1 {
		t.Fatalf("depth = %d, want 1", childPrincipal.Depth)
	}
	if strings.Join(childPrincipal.Scopes, ",") != "query_db" {
		t.Fatalf("child scopes = %v", childPrincipal.Scopes)
	}

	if _, _, err := m.MintDelegation(childPrincipal, "grandchild", []string{"execute_code"}); err == nil {
		t.Fatal("expected scope escalation to be rejected")
	}
}

func TestDelegationDepthLimit(t *testing.T) {
	m := testManager(t)
	root, _ := m.MintRoot("root")
	p, _ := m.Authenticate("Bearer " + root)

	for i := 0; i < maxDelegationDepth; i++ {
		token, _, err := m.MintDelegation(p, "child", []string{"query_db"})
		if err != nil {
			t.Fatalf("delegation %d: %v", i, err)
		}
		p, err = m.Authenticate("Bearer " + token)
		if err != nil {
			t.Fatalf("authenticate depth %d: %v", i, err)
		}
	}
	if _, _, err := m.MintDelegation(p, "too-deep", []string{"query_db"}); err == nil {
		t.Fatal("expected depth limit error")
	}
}

func TestRejectsAlgNoneAndWrongAlgorithm(t *testing.T) {
	m := testManager(t)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","scopes":["query_db"],"iss":"aegis-harness","aud":"aegis-gateway","exp":9999999999}`))
	if p, err := m.Authenticate("Bearer " + header + "." + payload + "."); err == nil || p != nil {
		t.Fatal("alg=none token was accepted")
	}

	claims := tokenClaims{
		Scopes: []string{"query_db"},
		Type:   TokenTypeAgent,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   "attacker",
			Audience:  jwt.ClaimStrings{Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed, err := tok.SignedString(m.secret)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := m.Authenticate("Bearer " + signed); err == nil || p != nil {
		t.Fatal("HS512 token was accepted")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	m := testManager(t)
	m.now = func() time.Time { return time.Now().Add(-48 * time.Hour) }
	token, err := m.MintRoot("root")
	if err != nil {
		t.Fatal(err)
	}
	m.now = time.Now

	if p, err := m.Authenticate("Bearer " + token); err == nil || p != nil {
		t.Fatal("expired token was accepted")
	}
}

func TestAdminToken(t *testing.T) {
	m := testManager(t)
	if !m.ValidateAdminToken("0123456789abcdef") {
		t.Fatal("valid admin token rejected")
	}
	if m.ValidateAdminToken("0123456789abcdeX") {
		t.Fatal("invalid admin token accepted")
	}
	if m.ValidateAdminToken("") {
		t.Fatal("empty admin token accepted")
	}
}

func TestInvalidIdentitiesRejected(t *testing.T) {
	m := testManager(t)
	for _, name := range []string{"", "a/b", "a b", "../root", "x\x00y", strings.Repeat("a", 129)} {
		if _, err := m.MintRoot(name); err == nil {
			t.Errorf("MintRoot(%q) succeeded", name)
		}
	}

	parent := &Principal{Subject: "parent", Scopes: []string{"query_db"}}
	for _, name := range []string{"", "a/b", strings.Repeat("a", 129)} {
		if _, _, err := m.MintDelegation(parent, name, []string{"query_db"}); err == nil {
			t.Errorf("MintDelegation child %q succeeded", name)
		}
	}
}

func TestUnknownScopesAreDiscarded(t *testing.T) {
	m := testManager(t)
	token, _, err := m.MintDelegation(&Principal{Subject: "p", Scopes: []string{"query_db"}}, "child", []string{"query_db", "root_shell"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.Authenticate("Bearer " + token)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Scopes) != 1 || p.Scopes[0] != "query_db" {
		t.Fatalf("scopes = %v", p.Scopes)
	}
}
