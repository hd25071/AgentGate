// Package auth issues and verifies the short-lived, scope-carrying tokens that
// are the only credential an Agent ever holds.
//
// Design note: the gateway holds the kubeconfig, the Redis password and the
// device credentials. The Agent holds a token that names *what it may do*, not
// *what it may log in as*. A leaked Agent token is therefore a scope problem,
// not a credential breach, and it expires on its own.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hd25071/AgentGate/internal/id"
	"github.com/hd25071/AgentGate/internal/policy"
)

// Errors returned by Verify. They are distinct so the audit log can tell an
// expired-but-authentic token from a forged one.
var (
	ErrMalformed = errors.New("token is malformed")
	ErrSignature = errors.New("token signature does not verify")
	ErrExpired   = errors.New("token is expired")
	ErrNotYet    = errors.New("token is not valid yet")
)

// Claims is the token payload.
type Claims struct {
	Subject string   `json:"sub"`
	Scopes  []string `json:"scopes"`
	Issuer  string   `json:"iss"`
	Issued  int64    `json:"iat"`
	Expires int64    `json:"exp"`
	TokenID string   `json:"jti"`
	Session string   `json:"sid"`
}

// Actor converts claims into the policy actor view.
func (c Claims) Actor() policy.Actor {
	return policy.Actor{Subject: c.Subject, Scopes: c.Scopes, Session: c.Session}
}

// Signer issues and verifies tokens with a symmetric key.
type Signer struct {
	secret []byte
	issuer string
	now    func() time.Time
}

// NewSigner builds a Signer. The secret must be at least 16 bytes: the gateway
// refuses to boot with a guessable key.
func NewSigner(secret []byte, issuer string) (*Signer, error) {
	if len(secret) < 16 {
		return nil, fmt.Errorf("token secret must be at least 16 bytes, got %d", len(secret))
	}
	if issuer == "" {
		issuer = "agentgate"
	}
	return &Signer{secret: secret, issuer: issuer, now: time.Now}, nil
}

// Issuer returns the configured issuer name.
func (s *Signer) Issuer() string { return s.issuer }

// Issue mints a token for a subject with the given scopes.
func (s *Signer) Issue(subject string, scopes []string, ttl time.Duration) (string, Claims, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", Claims{}, fmt.Errorf("token subject must not be empty")
	}
	if ttl <= 0 {
		return "", Claims{}, fmt.Errorf("token ttl must be positive")
	}
	norm, err := NormalizeScopes(scopes)
	if err != nil {
		return "", Claims{}, err
	}
	now := s.now()
	c := Claims{
		Subject: subject,
		Scopes:  norm,
		Issuer:  s.issuer,
		Issued:  now.Unix(),
		Expires: now.Add(ttl).Unix(),
		TokenID: id.New("tok"),
		Session: id.New("ses"),
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", Claims{}, err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	sig := s.sign(p)
	return p + "." + base64.RawURLEncoding.EncodeToString(sig), c, nil
}

// Verify checks structure, signature and validity window.
func (s *Signer) Verify(token string) (Claims, error) {
	var c Claims
	token = strings.TrimSpace(token)
	if token == "" {
		return c, fmt.Errorf("%w: empty token", ErrMalformed)
	}
	token = strings.TrimPrefix(token, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return c, fmt.Errorf("%w: expected two segments", ErrMalformed)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, fmt.Errorf("%w: signature is not base64url", ErrMalformed)
	}
	want := s.sign(parts[0])
	if subtle.ConstantTimeCompare(sig, want) != 1 {
		return c, ErrSignature
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return c, fmt.Errorf("%w: payload is not base64url", ErrMalformed)
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%w: payload did not decode: %v", ErrMalformed, err)
	}
	now := s.now().Unix()
	if c.Expires == 0 {
		return c, fmt.Errorf("%w: token has no expiry", ErrMalformed)
	}
	if now > c.Expires {
		return c, fmt.Errorf("%w: expired at %s", ErrExpired, time.Unix(c.Expires, 0).UTC().Format(time.RFC3339))
	}
	if c.Issued > now+60 {
		return c, fmt.Errorf("%w: issued in the future", ErrNotYet)
	}
	if c.Issuer != s.issuer {
		return c, fmt.Errorf("%w: issuer %q is not %q", ErrMalformed, c.Issuer, s.issuer)
	}
	if c.Subject == "" {
		return c, fmt.Errorf("%w: token has no subject", ErrMalformed)
	}
	return c, nil
}

func (s *Signer) sign(payload string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// knownScopes is the closed set of scopes the issuer will mint.
//
// A closed set matters: without it, a typo in a scope string silently produces
// a token that matches no policy rule, and the operator spends an afternoon
// debugging a "policy denies everything" report that is really a spelling bug.
var knownScopes = map[string]string{
	"redis:read":   "read Redis keys and metadata",
	"redis:write":  "mutate Redis data",
	"redis:delete": "delete Redis keys",
	"redis:admin":  "read Redis server configuration",
	"k8s:read":     "read Kubernetes objects",
	"k8s:write":    "create and update Kubernetes objects",
	"k8s:delete":   "delete Kubernetes objects",
	"k8s:exec":     "exec into pods",
	"vrp:config":   "read and change network device configuration",
	"break-glass":  "explicitly acknowledge an irreversible production change",
}

// KnownScopes returns the scope catalogue for help text and the approval UI.
func KnownScopes() map[string]string {
	out := make(map[string]string, len(knownScopes))
	for k, v := range knownScopes {
		out[k] = v
	}
	return out
}

// NormalizeScopes validates and de-duplicates a scope list.
func NormalizeScopes(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, ok := knownScopes[s]; !ok {
			return nil, fmt.Errorf("unknown scope %q (known: %s)", s, strings.Join(ScopeNames(), ", "))
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sortStrings(out)
	return out, nil
}

// ScopeNames lists the catalogue, sorted.
func ScopeNames() []string {
	out := make([]string, 0, len(knownScopes))
	for k := range knownScopes {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
