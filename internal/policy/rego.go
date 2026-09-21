package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/rego"

	"github.com/hd25071/AgentGate/policies"
)

// verdictQuery is the document the gateway asks for. Everything the gateway
// needs sits under this one path, so the bundle cannot accidentally hand back a
// half-built verdict.
const verdictQuery = "data.agentgate.decision.result"

// versionQuery resolves the bundle version declared in decision.rego.
const versionQuery = "data.agentgate.decision.bundle_version"

// RegoEngine is an in-process OPA evaluator.
type RegoEngine struct {
	prepared rego.PreparedEvalQuery
	versionQ rego.PreparedEvalQuery
	version  string
	source   string
	modules  int
}

// NewRegoEngine compiles the policy bundle.
//
// dirs may be empty, in which case the embedded bundle is used. A non-empty
// dirs list replaces the embedded bundle entirely: partial overrides would let
// a deployment silently drop rules, so the choice is all-or-nothing.
func NewRegoEngine(ctx context.Context, dirs []string) (*RegoEngine, error) {
	mods, source, err := loadModules(dirs)
	if err != nil {
		return nil, err
	}
	if len(mods) == 0 {
		return nil, fmt.Errorf("policy bundle is empty: refusing to start a gateway without rules")
	}

	prepare := func(query string) (rego.PreparedEvalQuery, error) {
		opts := []func(*rego.Rego){rego.Query(query)}
		for _, name := range sortedKeys(mods) {
			opts = append(opts, rego.Module(name, mods[name]))
		}
		return rego.New(opts...).PrepareForEval(ctx)
	}

	prepared, err := prepare(verdictQuery)
	if err != nil {
		return nil, fmt.Errorf("compile policy bundle from %s: %w", source, err)
	}
	versionQ, err := prepare(versionQuery)
	if err != nil {
		return nil, fmt.Errorf("compile policy bundle from %s: %w", source, err)
	}

	e := &RegoEngine{prepared: prepared, versionQ: versionQ, source: source, modules: len(mods)}
	rs, err := versionQ.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("evaluate bundle_version: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("policy bundle did not expose bundle_version")
	}
	e.version, _ = rs[0].Expressions[0].Value.(string)
	if e.version == "" {
		return nil, fmt.Errorf("policy bundle exposed an empty bundle_version")
	}
	return e, nil
}

// Version returns the bundle version declared in policies/decision.rego.
func (e *RegoEngine) Version() string { return e.version }

// Source describes where the bundle was loaded from.
func (e *RegoEngine) Source() string {
	return fmt.Sprintf("%s (%d modules)", e.source, e.modules)
}

// ModuleCount is reported by /healthz.
func (e *RegoEngine) ModuleCount() int { return e.modules }

// Decide evaluates policy.
//
// Any evaluation error yields a deny. The gateway treats "I could not decide"
// as "no", which is the only safe reading when the alternative is handing an
// LLM-driven process a production credential.
func (e *RegoEngine) Decide(ctx context.Context, in Input) (Decision, error) {
	if in.Action == nil {
		return failClosed("no action supplied"), fmt.Errorf("policy: nil action")
	}
	doc, err := buildInput(in)
	if err != nil {
		return failClosed(err.Error()), err
	}

	rs, err := e.prepared.Eval(ctx, rego.EvalInput(doc))
	if err != nil {
		return failClosed(fmt.Sprintf("policy evaluation failed: %v", err)), err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return failClosed("policy produced no result; fail closed"), nil
	}

	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return failClosed("policy result was not serializable"), err
	}
	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return failClosed("policy result had an unexpected shape"), err
	}
	d.Engine = "opa-embedded"
	if d.Decision == "" {
		return failClosed("policy result had no decision field"), nil
	}
	if d.Reasons == nil {
		d.Reasons = []string{}
	}
	if d.Flags == nil {
		d.Flags = []string{}
	}
	return d, nil
}

func failClosed(reason string) Decision {
	return Decision{
		Decision:      Deny,
		Risk:          "unknown",
		Reasons:       []string{reason},
		Flags:         []string{},
		RequiredScope: "unmapped",
		Engine:        "opa-embedded",
		EvalError:     reason,
	}
}

// loadModules reads .rego sources either from the embedded bundle or from disk.
func loadModules(dirs []string) (map[string]string, string, error) {
	if len(dirs) == 0 {
		m, err := modulesFromFS(policies.FS)
		return m, "embedded", err
	}
	mods := map[string]string{}
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, "_test.rego") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			mods[path] = string(b)
			return nil
		})
		if err != nil {
			return nil, "", fmt.Errorf("read policy dir %s: %w", dir, err)
		}
	}
	return mods, "disk:" + strings.Join(dirs, ","), nil
}

func modulesFromFS(fsys fs.FS) (map[string]string, error) {
	mods := map[string]string{}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") || strings.HasSuffix(e.Name(), "_test.rego") {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		mods[e.Name()] = string(b)
	}
	return mods, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
