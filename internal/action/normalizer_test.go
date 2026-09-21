package action

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Redis
//
// The point of these tests is not that "FLUSHALL" is parsed correctly -- it is
// that every *disguise* of FLUSHALL lands on the same normalized feature set.
// Policy never sees the string, so a disguise that survives normalization is
// the only way an injection can reach a ruleset that denies the plain form.
// ---------------------------------------------------------------------------

func redisTarget() Target {
	return Target{Kind: KindRedis, Name: "redis-1", Env: "staging"}
}

func mustNormalizeRedis(t *testing.T, command string) *Action {
	t.Helper()
	a, err := RedisNormalizer{}.Normalize(map[string]any{"command": command}, redisTarget())
	if err != nil {
		t.Fatalf("normalize %q: %v", command, err)
	}
	return a
}

func TestRedisVerbAndScope(t *testing.T) {
	cases := []struct {
		command     string
		wantVerb    Verb
		wantScope   BlastScope
		wantCommand string
		wantIrrev   bool
	}{
		{"GET user:1", VerbRead, ScopeKey, "GET", false},
		{"set user:1 alice", VerbWrite, ScopeKey, "SET", false},
		{"DEL user:1", VerbDelete, ScopeKey, "DEL", false},
		{"FLUSHALL", VerbDelete, ScopeDataset, "FLUSHALL", true},
		{"flushdb", VerbDelete, ScopeKeyspace, "FLUSHDB", true},
		{"KEYS *", VerbRead, ScopeKeyspace, "KEYS", false},
		{"EVAL \"return 1\" 0", VerbExec, ScopeKey, "EVAL", true},
		{"CONFIG SET maxmemory 1gb", VerbConfig, ScopeKey, "CONFIG", false},
		{"SHUTDOWN NOSAVE", VerbConfig, ScopeKey, "SHUTDOWN", true},
	}
	for _, tc := range cases {
		a := mustNormalizeRedis(t, tc.command)
		if a.Verb != tc.wantVerb {
			t.Errorf("%q: verb = %s, want %s", tc.command, a.Verb, tc.wantVerb)
		}
		if a.BlastRadius.Scope != tc.wantScope {
			t.Errorf("%q: scope = %s, want %s", tc.command, a.BlastRadius.Scope, tc.wantScope)
		}
		if got := a.ArgString("command_upper"); got != tc.wantCommand {
			t.Errorf("%q: command_upper = %s, want %s", tc.command, got, tc.wantCommand)
		}
		if a.BlastRadius.Irreversible != tc.wantIrrev {
			t.Errorf("%q: irreversible = %v, want %v", tc.command, a.BlastRadius.Irreversible, tc.wantIrrev)
		}
		if !a.ArgBool("command_known") {
			t.Errorf("%q: command_known = false, want the allowlist to recognise it", tc.command)
		}
	}
}

// Every disguise has to normalize to the same command_upper *and* to be marked
// as suspicious, so policy can deny both the action and the trick.
func TestRedisDisguisesAreFoldedAndFlagged(t *testing.T) {
	disguises := []struct {
		name    string
		command string
	}{
		{"lowercase", "flushall"},
		{"mixed case", "FlUsHaLL"},
		{"percent-encoded", "%46LUSHALL"},
		{"hex escapes", `\x46LUSHALL`},
		{"fullwidth", "ＦＬＵＳＨＡＬＬ"},
		{"cyrillic homoglyph", "FLUSHАLL"},
		{"quoted concatenation", `"FLU"+"SHALL"`},
		{"leading whitespace", "   FLUSHALL"},
		{"internal whitespace", "FLUSHALL   "},
	}
	for _, d := range disguises {
		t.Run(d.name, func(t *testing.T) {
			a := mustNormalizeRedis(t, d.command)
			if got := a.ArgString("command_upper"); got != "FLUSHALL" {
				t.Fatalf("command_upper = %q, want FLUSHALL (disguise survived normalization)", got)
			}
			if a.Verb != VerbDelete {
				t.Fatalf("verb = %s, want delete", a.Verb)
			}
			if a.BlastRadius.Scope != ScopeDataset {
				t.Fatalf("scope = %s, want dataset", a.BlastRadius.Scope)
			}
		})
	}

	// Lowercasing is ordinary normalization and must NOT be reported as an
	// attack; that is what "normalize before deciding" means.
	if a := mustNormalizeRedis(t, "flushall"); a.ArgBool("encoding_suspicious") {
		t.Error("plain lowercase was flagged as suspicious: normalization should be silent")
	}

	// Anything that needed decoding *is* reported, and policy uses that flag.
	for _, cmd := range []string{"%46LUSHALL", `\x46LUSHALL`, `"FLU"+"SHALL"`, "ＦＬＵＳＨＡＬＬ", "FLUSHАLL"} {
		a := mustNormalizeRedis(t, cmd)
		if !a.ArgBool("encoding_suspicious") {
			t.Errorf("%q: encoding_suspicious = false; the disguise would reach policy unlabelled", cmd)
		}
		if notes := a.ArgStrings("obfuscation_notes"); len(notes) == 0 {
			t.Errorf("%q: no obfuscation notes recorded for the audit trail", cmd)
		}
	}
}

// ---------------------------------------------------------------------------
// Case sensitivity of the data parameters
//
// Normalization folds the *command name*: "flushall", "FlUsHaLL" and
// "%46LUSHALL" are one command, and policy reads command_upper. Redis keys and
// values are a different matter -- they are byte strings, and "orders:1001" is
// not "ORDERS:1001". Folding them together would collapse two distinct actions
// onto one hash, and an approval given for one key would authorize the other.
// That is the "approve this, execute that" gap the hash exists to close, so the
// property gets its own test rather than riding along with the disguise test.
// ---------------------------------------------------------------------------

func TestRedisDataParametersKeepTheirCase(t *testing.T) {
	lower := mustNormalizeRedis(t, "DEL orders:1001")
	upper := mustNormalizeRedis(t, "DEL ORDERS:1001")

	// The command name is the same command in both spellings.
	if lower.ArgString("command_upper") != "DEL" || upper.ArgString("command_upper") != "DEL" {
		t.Fatalf("command_upper = %q / %q, want DEL in both",
			lower.ArgString("command_upper"), upper.ArgString("command_upper"))
	}
	// The key is not.
	if got := lower.ArgStrings("keys"); len(got) != 1 || got[0] != "orders:1001" {
		t.Errorf("DEL orders:1001 normalized its key to %q", got)
	}
	if got := upper.ArgStrings("keys"); len(got) != 1 || got[0] != "ORDERS:1001" {
		t.Errorf("DEL ORDERS:1001 normalized its key to %q", got)
	}
	if lower.Hash == upper.Hash {
		t.Fatal("DEL orders:1001 and DEL ORDERS:1001 hash the same: " +
			"an approval for one key would authorize the other")
	}

	// Values matter the same way as keys.
	for _, tc := range []struct{ a, b string }{
		{"SET backdoor 1", "SET BACKDOOR 1"},
		{"SET flag OFF", "SET flag off"},
		{"HSET user:1 role Admin", "HSET user:1 role admin"},
	} {
		if mustNormalizeRedis(t, tc.a).Hash == mustNormalizeRedis(t, tc.b).Hash {
			t.Errorf("%q and %q hash the same: a data value was case-folded", tc.a, tc.b)
		}
	}

	// Policy still sees one command in both spellings.
	if got := mustNormalizeRedis(t, "del orders:1001").ArgString("command_upper"); got != "DEL" {
		t.Errorf("command_upper = %q for a lowercase spelling, want DEL", got)
	}

	// The hash, by contrast, is allowed to keep the original spelling -- see
	// the comment on hashable. Over-sensitivity costs the approver a second
	// prompt; under-sensitivity is the hole. This assertion pins the direction
	// so that a later "cleanup" folding argv into the canonical form cannot
	// quietly make the hash blunter than the policy that reads it.
	if mustNormalizeRedis(t, "del orders:1001").Hash == lower.Hash {
		t.Error("the hash no longer distinguishes spellings of the command name: " +
			"the fold has leaked into the hash, which must stay at least as sensitive as policy")
	}
}

// The same rule for the other normalizers: a resource name is data, and so is
// everything inside a manifest.
func TestNonRedisDataParametersKeepTheirCase(t *testing.T) {
	cases := []struct {
		tool string
		a, b map[string]any
	}{
		{
			tool: "k8s_delete",
			a:    map[string]any{"kind": "Deployment", "name": "web", "namespace": "payments"},
			b:    map[string]any{"kind": "Deployment", "name": "WEB", "namespace": "payments"},
		},
		{
			tool: "k8s_apply",
			a: map[string]any{"namespace": "default", "manifest": map[string]any{
				"kind": "ConfigMap", "metadata": map[string]any{"name": "app-config"},
				"data": map[string]any{"log_level": "debug"}}},
			b: map[string]any{"namespace": "default", "manifest": map[string]any{
				"kind": "ConfigMap", "metadata": map[string]any{"name": "app-config"},
				"data": map[string]any{"log_level": "DEBUG"}}},
		},
	}
	for _, tc := range cases {
		first := mustNormalizeK8s(t, tc.tool, tc.a)
		second := mustNormalizeK8s(t, tc.tool, tc.b)
		if first.Hash == second.Hash {
			t.Errorf("%s: %v and %v hash the same: a data parameter was case-folded", tc.tool, tc.a, tc.b)
		}
	}
}

// The manifest fix above must not be paid for with formatting sensitivity.
// Re-serialising the same manifest -- different key order, different
// indentation -- is the same object, and the hash is over semantics.
func TestManifestReformattingDoesNotMoveTheHash(t *testing.T) {
	same := map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "web", "namespace": "payments"},
		"spec":       map[string]any{"replicas": 3},
	}
	reordered := map[string]any{
		"spec":       map[string]any{"replicas": 3},
		"metadata":   map[string]any{"namespace": "payments", "name": "web"},
		"kind":       "Deployment",
		"apiVersion": "apps/v1",
	}
	// The same object arriving as a JSON string rather than a parsed map.
	asString, err := json.Marshal(same)
	if err != nil {
		t.Fatal(err)
	}

	base := mustNormalizeK8s(t, "k8s_apply", map[string]any{"namespace": "payments", "manifest": same})
	for name, variant := range map[string]any{
		"reordered keys":  reordered,
		"json string":     string(asString),
		"indented string": reindent(t, asString),
	} {
		got := mustNormalizeK8s(t, "k8s_apply", map[string]any{"namespace": "payments", "manifest": variant})
		if got.Hash != base.Hash {
			t.Errorf("%s moved the hash: the manifest digest is over bytes, not semantics", name)
		}
	}
}

func reindent(t *testing.T, in []byte) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Indent(&buf, in, "  ", "\t"); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestRedisFragmentsAreCounted(t *testing.T) {
	// An injected log line that smuggles a second command past single-command
	// review is the canonical indirect-injection payload.
	a := mustNormalizeRedis(t, "GET health\nFLUSHALL")
	if got := a.ArgInt("fragments"); got != 2 {
		t.Fatalf("fragments = %d, want 2", got)
	}
	if a.ArgString("command_upper") != "GET" {
		t.Fatalf("the first command should be the classified one, got %s", a.ArgString("command_upper"))
	}
	if !strings.Contains(a.Raw, "FLUSHALL") {
		t.Error("the raw payload was not preserved for audit")
	}

	// A semicolon-joined pair is the same trick in a different vocabulary.
	// mustNormalizeRedis fails the test if this does not parse.
	b := mustNormalizeRedis(t, "GET a; DEL b")
	if got := b.ArgInt("fragments"); got != 2 {
		t.Fatalf("semicolon fragments = %d, want 2", got)
	}
}

func TestRedisUnknownCommandIsNotInVocabulary(t *testing.T) {
	a := mustNormalizeRedis(t, "MYSTERYCOMMAND foo")
	if a.ArgBool("command_known") {
		t.Fatal("an unknown command was reported as known")
	}
	// It must still be parseable: the *policy* refuses it, the parser does not
	// pretend it failed. That keeps "we do not understand this" distinguishable
	// from "this is malformed".
	if a.ArgString("command_upper") != "MYSTERYCOMMAND" {
		t.Fatalf("command_upper = %q", a.ArgString("command_upper"))
	}
}

func TestRedisConfigFeatures(t *testing.T) {
	a := mustNormalizeRedis(t, "CONFIG SET dir /var/lib/redis")
	if a.ArgString("subcommand_upper") != "SET" {
		t.Fatalf("subcommand_upper = %q", a.ArgString("subcommand_upper"))
	}
	if a.ArgString("config_param_upper") != "DIR" {
		t.Fatalf("config_param_upper = %q", a.ArgString("config_param_upper"))
	}
	if a.Resource.Type != "server-config" {
		t.Fatalf("resource type = %q, want server-config", a.Resource.Type)
	}

	b := mustNormalizeRedis(t, "CONFIG GET requirepass")
	if b.ArgString("config_param") != "requirepass" {
		t.Fatalf("config_param = %q, want requirepass", b.ArgString("config_param"))
	}
}

func TestRedisRejectsMalformedInput(t *testing.T) {
	cases := []map[string]any{
		{},
		{"command": ""},
		{"command": "GET 'unterminated"},
		{"command": 42},
	}
	for _, args := range cases {
		if _, err := (RedisNormalizer{}).Normalize(args, redisTarget()); err == nil {
			t.Errorf("args %#v were accepted", args)
		}
	}
}

// A quoted command name that contains a space is the "FLUSH ALL" trick: after
// naive tokenization it is one token, and a rule that matches on the whole
// token would never see FLUSH.
func TestRedisQuotedCommandWithSpaceIsResplit(t *testing.T) {
	a := mustNormalizeRedis(t, `"FLUSH ALL"`)
	if got := a.ArgString("command_upper"); got != "FLUSH" {
		t.Fatalf("command_upper = %q; the quoted name was not re-split", got)
	}
	// FLUSH is not a Redis command, so the allowlist refuses it. That is the
	// correct outcome: the gateway does not know what it does, so it does not
	// run it. What matters here is that it did not hide behind the quotes.
	if a.ArgBool("command_known") {
		t.Fatal("FLUSH was treated as a known command")
	}

	// The benign case must still work: a quoted name with no space is just a
	// spelled-out command.
	b := mustNormalizeRedis(t, `"SET" k v`)
	if b.ArgString("command_upper") != "SET" || !b.ArgBool("command_known") {
		t.Fatalf(`"SET" k v normalized to %q (known=%v)`, b.ArgString("command_upper"), b.ArgBool("command_known"))
	}
}

// ---------------------------------------------------------------------------
// Kubernetes
// ---------------------------------------------------------------------------

func k8sTarget(env string) Target {
	return Target{Kind: KindK8s, Name: "cluster-1", Env: env}
}

func mustNormalizeK8s(t *testing.T, tool string, args map[string]any) *Action {
	t.Helper()
	full := map[string]any{}
	for k, v := range args {
		full[k] = v
	}
	full["_tool"] = tool
	a, err := (K8sNormalizer{}).Normalize(full, k8sTarget("staging"))
	if err != nil {
		t.Fatalf("normalize %s: %v", tool, err)
	}
	return a
}

func TestK8sPrivilegedManifest(t *testing.T) {
	manifest := map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "escape", "namespace": "default"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"hostPID": true,
					"volumes": []any{map[string]any{"hostPath": map[string]any{"path": "/etc"}}},
					"containers": []any{map[string]any{
						"image": "alpine:latest",
						"securityContext": map[string]any{
							"privileged":   true,
							"capabilities": map[string]any{"add": []any{"SYS_ADMIN"}},
						},
					}},
				},
			},
		},
	}
	a := mustNormalizeK8s(t, "k8s_apply", map[string]any{"manifest": manifest, "kind": "Deployment", "name": "escape"})

	for _, feat := range []string{"privileged", "host_pid", "host_path_volume", "host_path_sensitive", "dangerous_capabilities", "no_resource_limits", "image_latest_tag"} {
		if !a.ArgBool(feat) {
			t.Errorf("feature %q was not extracted from the manifest", feat)
		}
	}
	if got := a.ArgString("host_path"); got != "/etc" {
		t.Errorf("host_path = %q", got)
	}
	if a.Verb != VerbWrite {
		t.Errorf("verb = %s, want write", a.Verb)
	}
}

func TestK8sNameMismatchIsDetected(t *testing.T) {
	// The URL path comes from the argument, the object identity from the
	// manifest. A reviewer and the API server would be looking at different
	// objects, so policy denies on the mismatch.
	manifest := map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "payments", "namespace": "default"},
	}
	a := mustNormalizeK8s(t, "k8s_apply", map[string]any{
		"manifest": manifest, "kind": "Deployment", "name": "web",
	})
	if !a.ArgBool("manifest_name_mismatch") {
		t.Fatal("manifest_name_mismatch was not detected")
	}
	if a.ArgString("manifest_name") != "payments" || a.ArgString("argument_name") != "web" {
		t.Fatalf("mismatch recorded as %q vs %q", a.ArgString("manifest_name"), a.ArgString("argument_name"))
	}
}

func TestK8sClusterScopedAndProtectedKinds(t *testing.T) {
	a := mustNormalizeK8s(t, "k8s_delete", map[string]any{"kind": "ClusterRoleBinding", "name": "platform-admin"})
	if !a.ArgBool("cluster_scoped") {
		t.Error("ClusterRoleBinding was not recognised as cluster-scoped")
	}
	if a.BlastRadius.Scope != ScopeCluster {
		t.Errorf("scope = %s, want cluster", a.BlastRadius.Scope)
	}
	if !a.ArgBool("rbac_escalation") {
		t.Error("ClusterRoleBinding was not recognised as an escalation vector")
	}

	b := mustNormalizeK8s(t, "k8s_delete", map[string]any{"kind": "PersistentVolumeClaim", "name": "orders-db-0", "namespace": "payments"})
	if !b.ArgBool("protected_kind") {
		t.Error("PVC deletion was not marked protected")
	}
	if !b.BlastRadius.Irreversible {
		t.Error("PVC deletion was not marked irreversible")
	}
}

func TestK8sRBACWildcardAndClusterAdminRef(t *testing.T) {
	role := mustNormalizeK8s(t, "k8s_apply", map[string]any{
		"kind": "ClusterRole",
		"name": "everything",
		"manifest": map[string]any{
			"kind":     "ClusterRole",
			"metadata": map[string]any{"name": "everything"},
			"rules":    []any{map[string]any{"apiGroups": []any{"*"}, "verbs": []any{"*"}, "resources": []any{"*"}}},
		},
	})
	if !role.ArgBool("rbac_wildcard") {
		t.Error("wildcard rules were not detected")
	}
	if !role.ArgBool("rbac_escalation") {
		t.Error("ClusterRole was not treated as an escalation vector")
	}

	binding := mustNormalizeK8s(t, "k8s_apply", map[string]any{
		"kind": "ClusterRoleBinding",
		"name": "admin",
		"manifest": map[string]any{
			"kind":     "ClusterRoleBinding",
			"metadata": map[string]any{"name": "admin"},
			"roleRef":  map[string]any{"kind": "ClusterRole", "name": "cluster-admin"},
		},
	})
	if !binding.ArgBool("rbac_cluster_admin") {
		t.Error("a cluster-admin roleRef was not detected")
	}
}

func TestK8sExecBecomesAPodAction(t *testing.T) {
	a := mustNormalizeK8s(t, "k8s_exec", map[string]any{
		"namespace": "payments", "pod": "checkout-7d9f", "container": "app",
		"command": []any{"sh", "-c", "cat /etc/passwd"},
	})
	if a.Verb != VerbExec {
		t.Fatalf("verb = %s, want exec", a.Verb)
	}
	if a.ArgString("kind") != "Pod" {
		t.Errorf("kind = %q, want Pod", a.ArgString("kind"))
	}
	if a.Resource.Name != "checkout-7d9f" {
		t.Errorf("resource name = %q", a.Resource.Name)
	}
	if got := a.ArgString("exec_command"); got != "sh -c cat /etc/passwd" {
		t.Errorf("exec_command = %q", got)
	}
	if a.BlastRadius.Scope != ScopeWorkload {
		t.Errorf("scope = %s, want workload", a.BlastRadius.Scope)
	}
}

func TestK8sScaleFeatures(t *testing.T) {
	a := mustNormalizeK8s(t, "k8s_scale", map[string]any{"kind": "Deployment", "name": "web", "replicas": 0})
	if !a.ArgBool("scale_to_zero") {
		t.Error("scale_to_zero was not set for replicas=0")
	}
	if a.Verb != VerbScale {
		t.Errorf("verb = %s, want scale", a.Verb)
	}
	if _, err := (K8sNormalizer{}).Normalize(map[string]any{"_tool": "k8s_scale", "kind": "Deployment", "name": "web"}, k8sTarget("staging")); err == nil {
		t.Error("k8s_scale without replicas was accepted")
	}
}

// A YAML manifest must be refused rather than half-parsed: the gateway runs no
// YAML parser over agent-controlled input on this surface.
func TestK8sRefusesYAMLAndUnknownTools(t *testing.T) {
	if _, err := (K8sNormalizer{}).Normalize(map[string]any{
		"_tool": "k8s_apply", "kind": "Deployment", "name": "web",
		"manifest": "kind: Deployment\nmetadata:\n  name: web\n",
	}, k8sTarget("staging")); err == nil {
		t.Fatal("a YAML manifest was accepted")
	}
	if _, err := (K8sNormalizer{}).Normalize(map[string]any{"_tool": "k8s_drain"}, k8sTarget("staging")); err == nil {
		t.Fatal("an unsupported k8s tool was accepted")
	}
	if _, err := (K8sNormalizer{}).Normalize(map[string]any{"_tool": "k8s_get"}, k8sTarget("staging")); err == nil {
		t.Fatal("a get without a kind was accepted")
	}
}

// ---------------------------------------------------------------------------
// VRP
// ---------------------------------------------------------------------------

func TestVRPConfigBlock(t *testing.T) {
	a, err := (VRPNormalizer{}).Normalize(map[string]any{
		"config": "interface GigabitEthernet0/0/1\n shutdown\n",
	}, Target{Kind: KindVRP, Name: "edge-1", Env: "staging"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if a.Verb != VerbDelete {
		t.Fatalf("verb = %s, want delete (shutdown takes the interface down)", a.Verb)
	}
	if a.ArgInt("shutdown_count") != 1 {
		t.Errorf("shutdown_count = %d", a.ArgInt("shutdown_count"))
	}
	if a.ArgInt("line_count") != 2 {
		t.Errorf("line_count = %d, want 2", a.ArgInt("line_count"))
	}
}

func TestVRPResetSavedConfigurationIsIrreversible(t *testing.T) {
	a, err := (VRPNormalizer{}).Normalize(map[string]any{
		"config": "reset saved-configuration\n",
	}, Target{Kind: KindVRP, Name: "edge-1", Env: "prod"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !a.ArgBool("resets_saved_config") {
		t.Error("reset saved-configuration was not detected")
	}
	if !a.BlastRadius.Irreversible {
		t.Error("wiping the saved configuration was not marked irreversible")
	}
	if !a.BlastRadius.Production {
		t.Error("the prod environment label was not reflected in the blast radius")
	}
}

func TestVRPACLAndPolicyBlocks(t *testing.T) {
	a, err := (VRPNormalizer{}).Normalize(map[string]any{
		"config": "acl number 3000\n rule 5 deny ip source any destination any\n" +
			"route-policy IMPORT-PEER permit node 10\n bgp 65001\n peer 10.0.0.2 as-number 65002\n",
	}, Target{Kind: KindVRP, Name: "edge-1", Env: "prod"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !a.ArgBool("acl_deny_all") {
		t.Error("acl_deny_all was not detected")
	}
	if a.Verb != VerbDelete {
		t.Error("a deny-all ACL should read as a destructive change, not a config tweak")
	}
	if a.ArgInt("route_policy_count") != 1 {
		t.Errorf("route_policy_count = %d", a.ArgInt("route_policy_count"))
	}
	if a.ArgInt("bgp_peer_count") != 1 {
		t.Errorf("bgp_peer_count = %d", a.ArgInt("bgp_peer_count"))
	}
	if a.BlastRadius.Scope != ScopeSite {
		t.Errorf("scope = %s, want site", a.BlastRadius.Scope)
	}
}

func TestVRPRejectsEmptyBlocks(t *testing.T) {
	for _, cfg := range []string{"", "   \n  \n", "! only a comment\n# and one more\n"} {
		if _, err := (VRPNormalizer{}).Normalize(map[string]any{"config": cfg}, Target{Kind: KindVRP, Name: "edge-1"}); err == nil {
			t.Errorf("empty config %q was accepted", cfg)
		}
	}
}
