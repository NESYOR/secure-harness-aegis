// Package auth mints and validates capability tokens used by the Aegis
// gateway. It deliberately fails closed: absent or malformed credentials never
// grant privileges.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// Issuer identifies tokens minted by this gateway.
	Issuer = "aegis-harness"
	// Audience prevents tokens minted for another service from being replayed.
	Audience = "aegis-gateway"

	TokenTypeAgent      = "agent"
	TokenTypeDelegation = "delegation"

	defaultDelegationTTL = 15 * time.Minute
	defaultRootTTL       = 24 * time.Hour
	maxDelegationDepth   = 3
)

// KnownScopes is the closed set of tool capabilities understood by the policy
// engine. Unknown scopes are discarded during token validation.
var KnownScopes = []string{"query_db", "execute_code", "http_request", "deploy_service"}

// identityPattern constrains subjects and session suffixes so that composite
// session IDs (subject + "/" + session) cannot collide.
var identityPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidIdentity reports whether s is a safe subject/session identifier.
func ValidIdentity(s string) bool { return identityPattern.MatchString(s) }

// Principal is an authenticated caller.
type Principal struct {
	Subject string
	Scopes  []string
	Type    string
	Depth   int
}

type tokenClaims struct {
	Scopes []string `json:"scopes"`
	Type   string   `json:"typ"`
	Parent string   `json:"parent,omitempty"`
	Depth  int      `json:"depth,omitempty"`
	jwt.RegisteredClaims
}

// Manager holds the process-local signing key and the HITL admin token.
type Manager struct {
	secret        []byte
	adminToken    string
	rootScopes    []string
	now           func() time.Time
	delegationTTL time.Duration
	rootTTL       time.Duration
}

// NewManager creates a manager with a fresh random signing key. If adminToken
// is empty a random one is generated and can be retrieved with AdminToken.
func NewManager(rootScopes []string, adminToken string) (*Manager, error) {
	scopes, err := normalizeScopes(rootScopes)
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating JWT signing key: %w", err)
	}

	if adminToken == "" {
		adminToken, err = randomToken(32)
		if err != nil {
			return nil, fmt.Errorf("generating admin token: %w", err)
		}
	}
	if len(adminToken) < 16 {
		return nil, errors.New("admin token must be at least 16 characters")
	}

	return &Manager{
		secret:        secret,
		adminToken:    adminToken,
		rootScopes:    scopes,
		now:           time.Now,
		delegationTTL: defaultDelegationTTL,
		rootTTL:       defaultRootTTL,
	}, nil
}

// AdminToken returns the token required by the HITL approval endpoint.
func (m *Manager) AdminToken() string { return m.adminToken }

// RootScopes returns the scopes granted to the root agent token.
func (m *Manager) RootScopes() []string { return append([]string(nil), m.rootScopes...) }

// MintRoot issues the root agent token injected into the wrapped subprocess.
func (m *Manager) MintRoot(subject string) (string, error) {
	if !ValidIdentity(subject) {
		return "", errors.New("subject must match [A-Za-z0-9._-]{1,128}")
	}
	return m.mint(tokenClaims{
		Scopes: m.rootScopes,
		Type:   TokenTypeAgent,
	}, subject, 0, "", m.rootTTL)
}

// MintDelegation issues a down-scoped token for a child agent. The granted
// scopes are the intersection of the parent's scopes and the request.
func (m *Manager) MintDelegation(parent *Principal, child string, requested []string) (string, []string, error) {
	if parent == nil {
		return "", nil, errors.New("parent principal is required")
	}
	if !ValidIdentity(child) {
		return "", nil, errors.New("child agent name must match [A-Za-z0-9._-]{1,128}")
	}
	if parent.Depth >= maxDelegationDepth {
		return "", nil, fmt.Errorf("delegation depth limit (%d) reached", maxDelegationDepth)
	}

	granted := intersect(parent.Scopes, requested)
	if len(granted) == 0 {
		return "", nil, errors.New("no requested scopes are available to delegate")
	}

	signed, err := m.mint(tokenClaims{
		Scopes: granted,
		Type:   TokenTypeDelegation,
		Parent: parent.Subject,
		Depth:  parent.Depth + 1,
	}, child, parent.Depth+1, parent.Subject, m.delegationTTL)
	if err != nil {
		return "", nil, err
	}
	return signed, granted, nil
}

func (m *Manager) mint(base tokenClaims, subject string, depth int, parent string, ttl time.Duration) (string, error) {
	now := m.now()
	base.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    Issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{Audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        randomID(),
	}
	base.Depth = depth
	base.Parent = parent

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, base)
	signed, err := tok.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return signed, nil
}

// Authenticate validates an Authorization header and returns the caller's
// principal. A missing or invalid credential is an error, never a default
// privilege grant.
func (m *Manager) Authenticate(authHeader string) (*Principal, error) {
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("missing bearer token")
	}
	raw := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if raw == "" {
		return nil, errors.New("empty bearer token")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(Issuer),
		jwt.WithAudience(Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(5*time.Second),
	)

	claims := &tokenClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	if claims.Type != TokenTypeAgent && claims.Type != TokenTypeDelegation {
		return nil, errors.New("invalid token type")
	}
	if claims.Depth < 0 || claims.Depth > maxDelegationDepth {
		return nil, errors.New("invalid delegation depth")
	}
	if !ValidIdentity(claims.Subject) {
		return nil, errors.New("token subject is missing or contains invalid characters")
	}

	return &Principal{
		Subject: claims.Subject,
		Scopes:  filterKnown(claims.Scopes),
		Type:    claims.Type,
		Depth:   claims.Depth,
	}, nil
}

// ValidateAdminToken compares a presented HITL admin token in constant time.
func (m *Manager) ValidateAdminToken(presented string) bool {
	if presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(m.adminToken)) == 1
}

// IsAdminRequest extracts and validates the admin token from a request.
func (m *Manager) IsAdminRequest(r *http.Request) bool {
	if tok := r.Header.Get("X-Aegis-Admin-Token"); tok != "" {
		return m.ValidateAdminToken(tok)
	}
	// Also accept "Authorization: Bearer <admin-token>" so the endpoint works
	// with generic tooling. Agent JWTs will not match the admin token.
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return m.ValidateAdminToken(strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	}
	return false
}

func normalizeScopes(in []string) ([]string, error) {
	out := filterKnown(in)
	if len(out) == 0 {
		return nil, errors.New("at least one known root scope is required")
	}
	return out, nil
}

func filterKnown(in []string) []string {
	allowed := make(map[string]struct{}, len(KnownScopes))
	for _, s := range KnownScopes {
		allowed[s] = struct{}{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if _, ok := allowed[s]; !ok {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func intersect(parent, requested []string) []string {
	parentSet := make(map[string]struct{}, len(parent))
	for _, s := range parent {
		parentSet[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range filterKnown(requested) {
		if _, ok := parentSet[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

func randomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is unrecoverable for a security control.
		panic("aegis: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
