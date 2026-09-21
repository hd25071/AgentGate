// Package action defines the central abstraction of AgentGate.
//
// The whole project rests on one idea: a policy engine must not reason about
// strings, it must reason about *semantics*. A tool call arrives as an opaque
// MCP argument blob ("FLUSHALL", "ReDiS-CLI --raw flushall", a K8s manifest, a
// VRP config block). Each normalizer turns that blob into a structured Action
// with a small, comparable feature set. Policy is then written against those
// features -- never against the raw text -- so casing tricks, fragmenting and
// encoding tricks cannot reach around the rules.
package action

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Kind identifies which subsystem an Action targets.
type Kind string

const (
	KindRedis Kind = "redis"
	KindK8s   Kind = "k8s"
	KindVRP   Kind = "vrp"
)

// Verb is the normalized intent of a tool call.
type Verb string

const (
	VerbRead   Verb = "read"
	VerbWrite  Verb = "write"
	VerbDelete Verb = "delete"
	VerbExec   Verb = "exec"
	VerbConfig Verb = "config"
	VerbScale  Verb = "scale"
)

// BlastScope describes how far an Action can reach, from one key to a whole site.
type BlastScope string

const (
	ScopeKey      BlastScope = "key"
	ScopeKeyspace BlastScope = "keyspace"
	ScopeDataset  BlastScope = "dataset"
	ScopeObject   BlastScope = "object"
	ScopeWorkload BlastScope = "workload"
	ScopeNS       BlastScope = "namespace"
	ScopeCluster  BlastScope = "cluster"
	ScopeDevice   BlastScope = "device"
	ScopeSite     BlastScope = "site"
	ScopeUnknown  BlastScope = "unknown"
)

// Target is the system an Action addresses. It never carries credentials; the
// gateway holds those and the Agent only ever names the target logically.
type Target struct {
	Kind     Kind   `json:"kind"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint,omitempty"`
	// Env is the declared environment ("prod" / "staging" / "dev"). Policy uses
	// it as a multiplier on risk, so it is taken from gateway config, not from
	// the Agent's request.
	Env string `json:"env,omitempty"`
}

// Resource names the concrete object being touched.
type Resource struct {
	Type      string `json:"type"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Count     int    `json:"count,omitempty"`
}

// BlastRadius is the pre-computed impact estimate used for risk tiering and for
// the approval UI.
type BlastRadius struct {
	Scope        BlastScope `json:"scope"`
	Affected     int        `json:"affected"`
	Irreversible bool       `json:"irreversible"`
	Production   bool       `json:"production"`
}

// Action is the normalized, hashable representation of one tool call.
type Action struct {
	ID          string         `json:"id"`
	Tool        string         `json:"tool"`
	Target      Target         `json:"target"`
	Verb        Verb           `json:"verb"`
	Resource    Resource       `json:"resource"`
	Args        map[string]any `json:"args"`
	BlastRadius BlastRadius    `json:"blast_radius"`
	// Raw preserves the original request for audit and replay. It is
	// deliberately excluded from the hash: the hash binds the *semantics*.
	Raw  string `json:"raw,omitempty"`
	Hash string `json:"hash"`
}

// hashable is the projection of an Action that participates in the action hash.
//
// Raw is excluded, so re-formatting the *request wrapper* (whitespace, a
// comment a human added, the order the caller wrote the arguments in) does not
// move the hash. Everything a normalizer lifted into the feature set is
// covered, including values that turn out to be semantically redundant such as
// the original casing of a command name.
//
// That last point is a deliberate asymmetry: the hash is allowed to be
// over-sensitive (two spellings of one command hash differently, and the
// approver is asked twice) but never under-sensitive (a value policy reads but
// the hash ignores, which is the gap an attacker would use to get "approve
// this, execute that").
type hashable struct {
	Tool        string         `json:"tool"`
	Target      Target         `json:"target"`
	Verb        Verb           `json:"verb"`
	Resource    Resource       `json:"resource"`
	Args        map[string]any `json:"args"`
	BlastRadius BlastRadius    `json:"blast_radius"`
}

// Canonical returns the deterministic JSON encoding of the semantic fields.
// encoding/json sorts map keys, so the output is stable across runs.
func (a *Action) Canonical() ([]byte, error) {
	h := hashable{
		Tool:        a.Tool,
		Target:      a.Target,
		Verb:        a.Verb,
		Resource:    a.Resource,
		Args:        a.SemanticArgs(),
		BlastRadius: a.BlastRadius,
	}
	return json.Marshal(h)
}

// SemanticArgs is the argument map as the policy engine sees it.
//
// This is deliberately the same projection that feeds the action hash. If the
// two ever diverged, an attacker could shift a value that policy reads while
// keeping the hash -- and therefore the approval -- unchanged.
func (a *Action) SemanticArgs() map[string]any {
	return normalizeArgs(a.Args)
}

// SemanticCopy returns an Action whose Args are the semantic projection. Used
// to build the policy input so that rego and the hash agree byte for byte.
func (a *Action) SemanticCopy() *Action {
	cp := *a
	cp.Args = a.SemanticArgs()
	return &cp
}

// normalizeArgs lowers lists of strings so that ordering of *unordered*
// collections does not perturb the hash. Sets are declared with a "set:" prefix
// convention by normalizers.
func normalizeArgs(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if strings.HasPrefix(k, "set:") {
			out[strings.TrimPrefix(k, "set:")] = sortedAny(v)
			continue
		}
		if strings.HasPrefix(k, "_") {
			// "_"-prefixed keys are advisory annotations (e.g. _note) and are
			// not part of the security-relevant identity.
			continue
		}
		out[k] = v
	}
	return out
}

func sortedAny(v any) any {
	switch t := v.(type) {
	case []string:
		cp := append([]string(nil), t...)
		sort.Strings(cp)
		return cp
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, fmt.Sprint(e))
		}
		sort.Strings(parts)
		return parts
	default:
		return v
	}
}

// Seal computes and stores the Action hash.
func (a *Action) Seal() error {
	c, err := a.Canonical()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(c)
	a.Hash = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}

// VerifyHash recomputes the hash and compares it to the sealed value. The
// approval flow calls this immediately before execution to close the
// time-of-check/time-of-use gap.
func (a *Action) VerifyHash(expected string) error {
	c, err := a.Canonical()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(c)
	got := "sha256:" + hex.EncodeToString(sum[:])
	if got != expected {
		return fmt.Errorf("%w: expected %s, recomputed %s", ErrHashMismatch, expected, got)
	}
	return nil
}

// ErrHashMismatch signals that an Action changed between approval and execution.
var ErrHashMismatch = fmt.Errorf("action hash mismatch")

// ShortHash renders the first 12 hex characters for UI display.
func ShortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 12 {
		return "sha256:" + h[:12]
	}
	return "sha256:" + h
}

// Summary is a one-line human description used in approval cards and audit.
func (a *Action) Summary() string {
	switch a.Target.Kind {
	case KindRedis:
		return fmt.Sprintf("redis %s on %s :: %s", a.Verb, a.Target.Name, a.Raw)
	case KindK8s:
		ns := a.Resource.Namespace
		if ns == "" {
			ns = "-"
		}
		return fmt.Sprintf("k8s %s %s/%s in %s", a.Verb, a.Resource.Type, a.Resource.Name, ns)
	case KindVRP:
		return fmt.Sprintf("vrp %s on %s (%d lines)", a.Verb, a.Target.Name, a.Resource.Count)
	default:
		return fmt.Sprintf("%s %s", a.Target.Kind, a.Verb)
	}
}

// Normalizer converts a raw tool argument map into a sealed Action.
type Normalizer interface {
	// Tool returns the MCP tool name this normalizer handles.
	Tool() string
	// Normalize parses args and produces a sealed Action. Implementations must
	// be pure: no I/O, no cluster access. Anything that needs to observe the
	// world belongs in preview or executor.
	Normalize(args map[string]any, tgt Target) (*Action, error)
}

// ---------------------------------------------------------------------------
// Feature accessors.
//
// Normalizers tag unordered collections with a "set:" prefix so the hash is
// stable regardless of ordering. These helpers hide that convention from
// adapters and from the policy input builder, which would otherwise have to
// know about it in two more places.
// ---------------------------------------------------------------------------

// Arg reads a feature by name, accepting either spelling.
func (a *Action) Arg(name string) (any, bool) {
	v, _, ok := a.argWithConvention(name)
	return v, ok
}

// argWithConvention looks a feature up under either spelling and reports which
// one matched. The flag matters: "keys" may be an ordered list that must keep
// its order, while "set:keys" is an unordered collection whose canonical form
// is sorted. Callers that hand values to adapters need to know which they got.
func (a *Action) argWithConvention(name string) (value any, unordered bool, ok bool) {
	if v, found := a.Args[name]; found {
		return v, false, true
	}
	if v, found := a.Args["set:"+name]; found {
		return v, true, true
	}
	return nil, false, false
}

// ArgString reads a string feature.
func (a *Action) ArgString(name string) string {
	v, ok := a.Arg(name)
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// ArgStrings reads a []string feature, tolerating []any.
//
// A collection the normalizer declared unordered ("set:") comes back sorted,
// because sorted is the form the policy engine decided on and the action hash
// covers. An adapter that saw insertion order would be looking at a different
// value from the one a human approved. Ordered collections keep their order.
func (a *Action) ArgStrings(name string) []string {
	v, unordered, ok := a.argWithConvention(name)
	if !ok || v == nil {
		return nil
	}
	var out []string
	switch t := v.(type) {
	case []string:
		out = append([]string(nil), t...)
	case []any:
		out = make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
	default:
		return nil
	}
	if unordered {
		sort.Strings(out)
	}
	return out
}

// ArgBool reads a boolean feature. A missing feature is false.
func (a *Action) ArgBool(name string) bool {
	v, ok := a.Arg(name)
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

// ArgInt reads a numeric feature. A missing feature is 0.
func (a *Action) ArgInt(name string) int {
	v, ok := a.Arg(name)
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}

// ErrInvalidArgs is returned by normalizers when the request cannot be parsed
// into a trustworthy Action. The gateway treats it as a hard deny: an
// unparseable request is exactly the shape an injection attack takes.
var ErrInvalidArgs = fmt.Errorf("invalid tool arguments")
