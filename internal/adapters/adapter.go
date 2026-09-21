// Package adapters is the bottom of the gateway: the only code that holds real
// credentials and talks to real systems.
//
// Two rules hold everywhere in this package:
//
//  1. Adapters receive an already-normalized, already-approved Action. They
//     never parse agent input and never make policy decisions.
//  2. Adapters return results that are sanitized before they leave. The
//     Agent's context window is the last place a production credential should
//     appear, because everything in it is attacker-reachable through indirect
//     prompt injection.
package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
)

// ErrNotSupported is returned by optional capabilities.
var ErrNotSupported = errors.New("adapter does not support this operation")

// Snapshot is the rollback material captured before a mutating action.
type Snapshot struct {
	Adapter  string          `json:"adapter"`
	Strategy string          `json:"strategy"`
	Data     json.RawMessage `json:"data"`
	TakenAt  int64           `json:"taken_at"`
	// Note is shown to the approver so they know exactly how much undo they
	// are getting. "best effort" is an honest answer; "" is not.
	Note string `json:"note"`
}

// PreviewResult is the output of a non-mutating dry run.
type PreviewResult struct {
	Adapter   string   `json:"adapter"`
	Supported bool     `json:"supported"`
	Impact    string   `json:"impact"`
	Findings  []string `json:"findings"`
	Details   any      `json:"details,omitempty"`
	// Mode names the backing implementation ("cluster", "mock", "simulator").
	// It travels with every preview so a reader can never mistake a simulated
	// dry run for a real one.
	Mode string `json:"mode,omitempty"`
}

// Result is what an execution produced.
type Result struct {
	Adapter string `json:"adapter"`
	Status  string `json:"status"` // "ok" | "noop" | "partial"
	Summary string `json:"summary"`
	Output  any    `json:"output,omitempty"`
	Mutated bool   `json:"mutated"`
}

// Adapter is implemented per target system.
type Adapter interface {
	Kind() action.Kind
	Name() string
	// Health probes the target so /healthz can report a truthful state.
	Health(ctx context.Context) error
	// Snapshot captures rollback material. It is called for every mutating
	// action, before execution, and its cost is bounded by config.
	Snapshot(ctx context.Context, a *action.Action) (Snapshot, error)
	// Preview performs the non-mutating dry run.
	Preview(ctx context.Context, a *action.Action) (PreviewResult, error)
	// Execute performs the action.
	Execute(ctx context.Context, a *action.Action) (Result, error)
	// Rollback undoes a previous Execute using its snapshot.
	Rollback(ctx context.Context, a *action.Action, s Snapshot) error
}

// Registry resolves an Action to its adapter.
type Registry struct {
	byKind map[action.Kind]Adapter
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{byKind: map[action.Kind]Adapter{}}
}

// Register adds an adapter.
func (r *Registry) Register(a Adapter) { r.byKind[a.Kind()] = a }

// Get returns the adapter for a kind.
func (r *Registry) Get(k action.Kind) (Adapter, error) {
	a, ok := r.byKind[k]
	if !ok {
		return nil, fmt.Errorf("no adapter registered for target kind %q", k)
	}
	return a, nil
}

// Kinds lists registered target kinds.
func (r *Registry) Kinds() []action.Kind {
	out := make([]action.Kind, 0, len(r.byKind))
	for k := range r.byKind {
		out = append(out, k)
	}
	return out
}

// HealthAll probes every adapter and returns a per-target report.
func (r *Registry) HealthAll(ctx context.Context) map[string]string {
	out := map[string]string{}
	for k, a := range r.byKind {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := a.Health(ctx)
		cancel()
		if err != nil {
			out[string(k)] = "unhealthy: " + err.Error()
			continue
		}
		out[string(k)] = "ok"
	}
	return out
}

// ReseedSimulator restores the in-memory Kubernetes simulator, if one is
// registered. Returns false when the registered adapter is a real cluster, so
// the caller can say "not a simulator" instead of pretending it worked.
func (r *Registry) ReseedSimulator() bool {
	a, ok := r.byKind[action.KindK8s]
	if !ok {
		return false
	}
	m, ok := a.(*MockK8sAdapter)
	if !ok {
		return false
	}
	m.Reseed()
	return true
}

// ---------------------------------------------------------------------------
// Result sanitization
// ---------------------------------------------------------------------------

// sensitiveMarkers are substrings that, when they show up in a target's reply,
// mean the reply is carrying something the Agent should not see. The list is
// deliberately blunt: Redis and Kubernetes both leak credentials through
// innocuous-looking read paths, and a false positive here costs a retry while a
// false negative costs a production secret.
// Every marker is folded to lower case at declaration time. Matching runs
// against a lowercased haystack, so a marker written in its natural spelling
// ("-----BEGIN") would silently never match -- a quiet false negative on the
// one class of value where a false negative is a leaked key. Deriving them
// rather than trusting the list is what makes that mistake impossible.
var sensitiveMarkers = lowerAll([]string{
	"requirepass",
	"masterauth",
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api_key",
	"authorization",
	// A bearer credential is a credential whether or not the word "token"
	// appears next to it. Without this marker a JWT in a reply body would go
	// straight into the Agent's context window.
	"bearer ",
	"private_key",
	"private key", // the PEM spelling, which uses a space
	"-----begin",
	"begin rsa private key",
	"begin openssh private key",
	"client_secret",
	"ssl_certificate_key",
})

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// Sanitize walks an adapter result and redacts credential-shaped values.
//
// It is a belt-and-braces layer: policy already blocks `CONFIG GET requirepass`
// and Secret reads. This exists because policy is a rule set and rule sets have
// gaps, whereas "redact before it enters the context window" has none.
func Sanitize(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return sanitizeString(t)
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = sanitizeString(s)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Sanitize(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSensitiveKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[SanitizeKey(k)] = Sanitize(val)
		}
		return out
	case Result:
		t.Summary = sanitizeString(t.Summary)
		t.Output = Sanitize(t.Output)
		return t
	default:
		return v
	}
}

func isSensitiveKey(k string) bool {
	lk := strings.ToLower(k)
	for _, m := range sensitiveMarkers {
		if strings.Contains(lk, m) {
			return true
		}
	}
	return false
}

// SanitizeKey normalises a config key for display.
func SanitizeKey(k string) string { return k }

func sanitizeString(s string) string {
	ls := strings.ToLower(s)
	for _, m := range sensitiveMarkers {
		if strings.Contains(ls, m) {
			return Redact(s)
		}
	}
	return s
}

// Redact keeps the shape of a value while removing its content, so an operator
// can still see that something was there.
func Redact(s string) string {
	if len(s) <= 8 {
		return "[REDACTED]"
	}
	return s[:4] + "[REDACTED]" + fmt.Sprint(len(s)-4) + "ch"
}
