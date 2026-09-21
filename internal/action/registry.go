package action

import "fmt"

// Registry dispatches a tool call to the normalizer that understands it.
//
// Adding a new target system means adding a Normalizer here and a matching
// policies/<target>.rego. Nothing in the MCP layer, approval flow or executor
// changes -- that is the point of the Action abstraction.
type Registry struct {
	byTool map[string]Normalizer
}

func NewRegistry() *Registry {
	r := &Registry{byTool: map[string]Normalizer{}}
	r.Register(RedisNormalizer{})
	r.Register(VRPNormalizer{})
	k8s := K8sNormalizer{}
	// The K8s normalizer is deliberately registered per concrete tool so the
	// declared tool list and the normalizer set cannot drift apart.
	for tool := range k8sTools {
		r.byTool[tool] = k8sNormalizerAdapter{tool: tool, inner: k8s}
	}
	return r
}

// Register adds a normalizer keyed by the tool name it handles.
func (r *Registry) Register(n Normalizer) {
	r.byTool[n.Tool()] = n
}

// Supports reports whether a tool has a normalizer.
func (r *Registry) Supports(tool string) bool {
	_, ok := r.byTool[tool]
	return ok
}

// Normalize produces a sealed Action for a tool call.
func (r *Registry) Normalize(tool string, args map[string]any, tgt Target) (*Action, error) {
	n, ok := r.byTool[tool]
	if !ok {
		return nil, fmt.Errorf("%w: no normalizer registered for tool %q", ErrInvalidArgs, tool)
	}
	// Copy so normalizers cannot mutate the caller's map, and stamp the tool
	// name where the normalizer needs it.
	cp := make(map[string]any, len(args)+1)
	for k, v := range args {
		cp[k] = v
	}
	cp["_tool"] = tool
	return n.Normalize(cp, tgt)
}

// Tools returns the tool names this registry can normalize. Used by tests to
// assert that every advertised MCP tool is actually documented in policy.
func (r *Registry) Tools() []string {
	out := make([]string, 0, len(r.byTool))
	for k := range r.byTool {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// k8sNormalizerAdapter pins a single tool name onto the shared K8s normalizer.
type k8sNormalizerAdapter struct {
	tool  string
	inner K8sNormalizer
}

func (a k8sNormalizerAdapter) Tool() string { return a.tool }
func (a k8sNormalizerAdapter) Normalize(args map[string]any, tgt Target) (*Action, error) {
	return a.inner.Normalize(args, tgt)
}
