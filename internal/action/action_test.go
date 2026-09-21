package action

import (
	"encoding/json"
	"strings"
	"testing"
)

// The action hash is the anchor of the whole approval story: an approver signs
// off on a hash, and the executor refuses to run anything that does not
// recompute to it. These tests pin the two properties that makes it useful --
// stability (same semantics => same hash) and sensitivity (different semantics
// => different hash).
func TestSealIsStableAndSensitive(t *testing.T) {
	base := func() *Action {
		return &Action{
			Tool:     "redis_exec",
			Target:   Target{Kind: KindRedis, Name: "redis-1", Env: "staging"},
			Verb:     VerbDelete,
			Resource: Resource{Type: "keyspace", Name: "*", Count: 0},
			Args: map[string]any{
				"command_upper": "FLUSHDB",
				"argv":          []string{"FLUSHDB"},
				"set:keys":      []string{"b", "a"},
			},
		}
	}

	first := base()
	if err := first.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Same semantics, different insertion order and a different Raw: the hash
	// must not move. Raw is deliberately outside the hash, which is why a
	// re-spelled request deduplicates in the approval queue.
	second := base()
	second.Raw = "FLUSHDB   -- a human wrote this differently"
	second.Args["set:keys"] = []string{"a", "b"}
	if err := second.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if first.Hash != second.Hash {
		t.Fatalf("hash is not stable across equivalent actions:\n %s\n %s", first.Hash, second.Hash)
	}

	// One semantic feature changes: the hash must move.
	changed := base()
	changed.Args["command_upper"] = "FLUSHALL"
	if err := changed.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if changed.Hash == first.Hash {
		t.Fatal("changing command_upper did not change the hash: the approval binding is worthless")
	}

	// So must a target change: the same verb on a different cluster is a
	// different action.
	retargeted := base()
	retargeted.Target = Target{Kind: KindRedis, Name: "redis-2", Env: "prod"}
	retargeted.Raw = second.Raw
	if err := retargeted.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if retargeted.Hash == first.Hash {
		t.Fatal("changing the target did not change the hash")
	}
}

func TestVerifyHashDetectsTampering(t *testing.T) {
	a := &Action{
		Tool:     "k8s_delete",
		Target:   Target{Kind: KindK8s, Name: "cluster", Env: "staging"},
		Verb:     VerbDelete,
		Resource: Resource{Type: "Deployment", Name: "web", Namespace: "default"},
		Args:     map[string]any{"kind_lower": "deployment"},
	}
	if err := a.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	approved := a.Hash

	if err := a.VerifyHash(approved); err != nil {
		t.Fatalf("untampered action failed verification: %v", err)
	}

	// Simulate an attacker editing the stored action between approval and
	// execution -- the classic TOCTOU move.
	a.Resource.Name = "payments"
	err := a.VerifyHash(approved)
	if err == nil {
		t.Fatal("tampered action passed verification")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected a hash mismatch error, got %v", err)
	}
}

// "_"-prefixed keys are annotations and "set:"-prefixed keys are unordered
// collections. Both conventions have to be honoured by the same projection that
// the hash uses, or policy could read a value the hash does not cover.
func TestSemanticArgsProjection(t *testing.T) {
	a := &Action{Args: map[string]any{
		"_notes":   []string{"advisory only"},
		"command":  "GET k",
		"set:keys": []string{"z", "a", "m"},
	}}

	got := a.SemanticArgs()
	if _, ok := got["_notes"]; ok {
		t.Error("advisory _notes leaked into the semantic projection")
	}
	if _, ok := got["set:keys"]; ok {
		t.Error("set: prefix survived into the semantic projection")
	}
	keys, ok := got["keys"].([]string)
	if !ok {
		t.Fatalf("sorted key set missing or wrong type: %#v", got["keys"])
	}
	if strings.Join(keys, ",") != "a,m,z" {
		t.Fatalf("key set was not sorted: %v", keys)
	}

	// The accessors must accept both spellings so adapters do not have to know
	// about the convention.
	if got := a.ArgStrings("keys"); strings.Join(got, ",") != "a,m,z" {
		t.Fatalf("ArgStrings(keys) = %v", got)
	}
}

func TestCanonicalIsDeterministicJSON(t *testing.T) {
	a := &Action{
		Tool:   "net_config",
		Target: Target{Kind: KindVRP, Name: "edge-1"},
		Verb:   VerbConfig,
		Args:   map[string]any{"line_count": 3, "set:bgp_peers": []string{"10.0.0.2", "10.0.0.1"}},
	}
	one, err := a.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	two, err := a.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if string(one) != string(two) {
		t.Fatal("Canonical is not deterministic")
	}
	var doc map[string]any
	if err := json.Unmarshal(one, &doc); err != nil {
		t.Fatalf("canonical output is not JSON: %v", err)
	}
	if _, ok := doc["raw"]; ok {
		t.Error("raw leaked into the hashed projection")
	}
}

func TestShortHash(t *testing.T) {
	full := "sha256:0123456789abcdef0123456789abcdef"
	if got := ShortHash(full); got != "sha256:0123456789ab" {
		t.Fatalf("ShortHash = %q", got)
	}
	if got := ShortHash("abcd"); got != "sha256:abcd" {
		t.Fatalf("ShortHash on a short string = %q", got)
	}
}

func TestRegistryRefusesUnknownTool(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Normalize("k8s_pod_escape", map[string]any{}, Target{Kind: KindK8s}); err == nil {
		t.Fatal("an unregistered tool was normalized")
	}
	if r.Supports("k8s_pod_escape") {
		t.Fatal("registry claims to support an unknown tool")
	}
	// Every advertised tool must actually have a normalizer: a tool that
	// reaches the MCP surface without one is a hole in the policy layer.
	for _, tool := range []string{"redis_exec", "net_config", "k8s_get", "k8s_apply", "k8s_delete", "k8s_exec", "k8s_scale"} {
		if !r.Supports(tool) {
			t.Errorf("no normalizer registered for %q", tool)
		}
	}
}
