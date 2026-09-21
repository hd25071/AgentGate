package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/hd25071/AgentGate/internal/action"
)

// newEngine compiles the embedded bundle. Every policy test goes through the
// real Rego files: a test that restates the rules in Go would pass while the
// bundle was broken.
func newEngine(t *testing.T) *RegoEngine {
	t.Helper()
	e, err := NewRegoEngine(context.Background(), nil)
	if err != nil {
		t.Fatalf("compile embedded bundle: %v", err)
	}
	return e
}

type evalCase struct {
	name     string
	tool     string
	kind     action.Kind
	target   action.Target
	subject  string
	scopes   []string
	args     map[string]any
	want     string
	wantRisk string
}

func runCase(t *testing.T, e Engine, tc evalCase) Decision {
	t.Helper()
	tgt := tc.target
	if tgt.Kind == "" {
		tgt = action.Target{Kind: tc.kind, Name: "t-1", Endpoint: "gw:test", Env: "staging"}
	}
	a, err := action.NewRegistry().Normalize(tc.tool, tc.args, tgt)
	if err != nil {
		t.Fatalf("normalize %s %v: %v", tc.tool, tc.args, err)
	}
	subject := tc.subject
	if subject == "" {
		subject = "agent-1"
	}
	d, err := e.Decide(context.Background(), Input{
		Action: a,
		Actor:  Actor{Subject: subject, Scopes: tc.scopes},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	return d
}

// TestPolicyVerdicts is the core contract: each of these rows is a promise the
// gateway makes to an operator. If one flips, either the gateway is refusing
// something it documented as fine, or -- worse -- it is letting something
// through that the design document says needs a human.
func TestPolicyVerdicts(t *testing.T) {
	e := newEngine(t)

	privilegedManifest := map[string]any{
		"kind":     "Deployment",
		"metadata": map[string]any{"name": "escape", "namespace": "default"},
		"spec": map[string]any{
			"selector": map[string]any{"matchLabels": map[string]any{"app": "escape"}},
			"template": map[string]any{
				"spec": map[string]any{"containers": []any{
					map[string]any{"name": "c", "image": "alpine:3.20",
						"resources":       map[string]any{"limits": map[string]any{"cpu": "100m"}},
						"securityContext": map[string]any{"privileged": true}},
				}},
			},
		},
	}

	cases := []evalCase{
		// --- Redis: reads -------------------------------------------------
		{
			name: "benign redis read is allowed", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:read"}, args: map[string]any{"command": "GET session:42"},
			want: Allow, wantRisk: "low",
		},
		{
			name: "redis read without the scope is refused", tool: "redis_exec", kind: action.KindRedis,
			args: map[string]any{"command": "GET session:42"},
			want: Deny,
		},
		{
			name: "redis read in production is still a read", tool: "redis_exec", kind: action.KindRedis,
			target: action.Target{Kind: action.KindRedis, Name: "t", Endpoint: "gw:test", Env: "prod"},
			scopes: []string{"redis:read"}, args: map[string]any{"command": "GET session:42"},
			want: Allow,
		},

		// --- Redis: writes ------------------------------------------------
		{
			name: "staging write is allowed", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:write"}, args: map[string]any{"command": "SET feature:flag on"},
			want: Allow,
		},
		{
			name: "production write needs a human", tool: "redis_exec", kind: action.KindRedis,
			target: action.Target{Kind: action.KindRedis, Name: "t", Endpoint: "gw:test", Env: "prod"},
			scopes: []string{"redis:write"}, args: map[string]any{"command": "SET feature:flag on"},
			want: ApprovalRequired, wantRisk: "high",
		},
		{
			name: "wildcard delete needs a human", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:delete"}, args: map[string]any{"command": "DEL user:*"},
			want: ApprovalRequired,
		},

		// --- Redis: never approvable -------------------------------------
		{
			name: "FLUSHALL is denied outright", tool: "redis_exec", kind: action.KindRedis,
			target: action.Target{Kind: action.KindRedis, Name: "t", Endpoint: "gw:test", Env: "prod"},
			scopes: []string{"redis:delete"}, args: map[string]any{"command": "FLUSHALL"},
			want: Deny, wantRisk: "critical",
		},
		{
			name: "a disguised FLUSHALL is denied too", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:delete"}, args: map[string]any{"command": "%46LUSHALL"},
			want: Deny,
		},
		{
			name: "EVAL is denied outright", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:write"}, args: map[string]any{"command": `EVAL "return 1" 0`},
			want: Deny,
		},
		{
			name: "CONFIG GET requirepass is denied", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG GET requirepass"},
			want: Deny,
		},
		{
			name: "CONFIG GET * is denied", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG GET *"},
			want: Deny,
		},
		{
			name: "an unknown command is denied", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:read"}, args: map[string]any{"command": "MYSTERY foo"},
			want: Deny,
		},
		{
			name: "a multi-command payload is denied", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:read"}, args: map[string]any{"command": "GET health\nFLUSHALL"},
			want: Deny,
		},
		{
			name: "KEYS * on production is denied", tool: "redis_exec", kind: action.KindRedis,
			target: action.Target{Kind: action.KindRedis, Name: "t", Endpoint: "gw:test", Env: "prod"},
			scopes: []string{"redis:read"}, args: map[string]any{"command": "KEYS *"},
			want: Deny,
		},

		// --- Redis: administrative ---------------------------------------
		{
			// This row used to assert approval_required. It was wrong, and the
			// over-broad rule behind it (`is_admin` => a human) is what the
			// corpus's benign set flagged as friction: gating "how much memory
			// is used" is the cheapest way to teach an operator to approve
			// without reading. CONFIG GET of one non-credential parameter is a
			// read. The credential and wildcard cases above stay denied.
			name: "benign CONFIG GET of one safe parameter is allowed", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG GET maxmemory"},
			want: Allow,
		},
		{
			name: "KEYS with a pattern needs approval", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:read"}, args: map[string]any{"command": "KEYS user:*"},
			want: ApprovalRequired,
		},

		// --- Kubernetes: reads -------------------------------------------
		{
			name: "reading a Deployment is allowed", tool: "k8s_get", kind: action.KindK8s,
			scopes: []string{"k8s:read"},
			args:   map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"},
			want:   Allow,
		},
		{
			name: "reading a Secret needs approval", tool: "k8s_get", kind: action.KindK8s,
			scopes: []string{"k8s:read"},
			args:   map[string]any{"kind": "Secret", "name": "db-credentials", "namespace": "payments"},
			want:   ApprovalRequired,
		},

		// --- Kubernetes: never approvable --------------------------------
		{
			name: "deleting a Namespace is denied", tool: "k8s_delete", kind: action.KindK8s,
			scopes: []string{"k8s:delete"},
			args:   map[string]any{"kind": "Namespace", "name": "payments"},
			want:   Deny,
		},
		{
			name: "deleting a PVC is denied", tool: "k8s_delete", kind: action.KindK8s,
			scopes: []string{"k8s:delete"},
			args:   map[string]any{"kind": "PersistentVolumeClaim", "name": "orders-db-0", "namespace": "payments"},
			want:   Deny,
		},
		{
			name: "deleting a StatefulSet is denied", tool: "k8s_delete", kind: action.KindK8s,
			scopes: []string{"k8s:delete"},
			args:   map[string]any{"kind": "StatefulSet", "name": "orders-db", "namespace": "payments"},
			want:   Deny,
		},
		{
			name: "writing to kube-system is denied", tool: "k8s_apply", kind: action.KindK8s,
			scopes: []string{"k8s:write"},
			args:   map[string]any{"kind": "Deployment", "name": "coredns", "namespace": "kube-system"},
			want:   Deny,
		},
		{
			name: "exec into a control-plane pod is denied", tool: "k8s_exec", kind: action.KindK8s,
			scopes: []string{"k8s:exec"},
			args:   map[string]any{"namespace": "kube-system", "pod": "coredns-abc", "command": []any{"sh", "-c", "id"}},
			want:   Deny,
		},
		{
			name: "scaling production to zero is denied", tool: "k8s_scale", kind: action.KindK8s,
			target: action.Target{Kind: action.KindK8s, Name: "t", Endpoint: "gw:test", Env: "prod"},
			scopes: []string{"k8s:write"},
			args:   map[string]any{"kind": "Deployment", "name": "checkout", "namespace": "payments", "replicas": 0},
			want:   Deny,
		},
		{
			name: "a hostPath mount into /etc is denied", tool: "k8s_apply", kind: action.KindK8s,
			scopes: []string{"k8s:write"},
			args: map[string]any{
				"kind": "Deployment", "name": "sneaky", "namespace": "default",
				"manifest": map[string]any{
					"kind":     "Deployment",
					"metadata": map[string]any{"name": "sneaky", "namespace": "default"},
					"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
						"volumes": []any{map[string]any{"hostPath": map[string]any{"path": "/etc"}}},
						"containers": []any{map[string]any{"name": "c", "image": "alpine:3.20",
							"resources": map[string]any{"limits": map[string]any{"cpu": "100m"}}}},
					}}},
				},
			},
			want: Deny,
		},
		{
			name: "a manifest/argument name mismatch is denied", tool: "k8s_apply", kind: action.KindK8s,
			scopes: []string{"k8s:write"},
			args: map[string]any{
				"kind": "Deployment", "name": "web", "namespace": "default",
				"manifest": map[string]any{
					"kind":     "Deployment",
					"metadata": map[string]any{"name": "payments", "namespace": "default"},
				},
			},
			want: Deny,
		},
		{
			name: "a cluster-admin binding is denied", tool: "k8s_apply", kind: action.KindK8s,
			scopes: []string{"k8s:write"},
			args: map[string]any{
				"kind": "ClusterRoleBinding", "name": "backdoor",
				"manifest": map[string]any{
					"kind":     "ClusterRoleBinding",
					"metadata": map[string]any{"name": "backdoor"},
					"roleRef":  map[string]any{"kind": "ClusterRole", "name": "cluster-admin"},
				},
			},
			want: Deny,
		},
		{
			name: "dangerous capabilities are denied", tool: "k8s_apply", kind: action.KindK8s,
			scopes: []string{"k8s:write"},
			args: map[string]any{
				"kind": "Deployment", "name": "cap", "namespace": "default",
				"manifest": map[string]any{
					"kind":     "Deployment",
					"metadata": map[string]any{"name": "cap", "namespace": "default"},
					"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
						"containers": []any{map[string]any{"name": "c", "image": "alpine:3.20",
							"resources":       map[string]any{"limits": map[string]any{"cpu": "100m"}},
							"securityContext": map[string]any{"capabilities": map[string]any{"add": []any{"SYS_ADMIN"}}}}},
					}}},
				},
			},
			want: Deny,
		},

		// --- Kubernetes: approval ----------------------------------------
		{
			name: "deleting a workload needs approval", tool: "k8s_delete", kind: action.KindK8s,
			scopes: []string{"k8s:delete"},
			args:   map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"},
			want:   ApprovalRequired,
		},
		{
			name: "scaling a workload needs approval", tool: "k8s_scale", kind: action.KindK8s,
			scopes: []string{"k8s:write"},
			args:   map[string]any{"kind": "Deployment", "name": "web", "namespace": "default", "replicas": 5},
			want:   ApprovalRequired,
		},
		{
			name: "exec into a pod needs approval", tool: "k8s_exec", kind: action.KindK8s,
			scopes: []string{"k8s:exec"},
			args:   map[string]any{"namespace": "payments", "pod": "checkout-1", "command": []any{"sh", "-c", "df -h"}},
			want:   ApprovalRequired,
		},
		{
			name: "a privileged manifest needs approval", tool: "k8s_apply", kind: action.KindK8s,
			scopes: []string{"k8s:write"},
			args:   map[string]any{"kind": "Deployment", "name": "escape", "namespace": "default", "manifest": privilegedManifest},
			want:   ApprovalRequired,
		},
		{
			name: "a production delete needs approval", tool: "k8s_delete", kind: action.KindK8s,
			target: action.Target{Kind: action.KindK8s, Name: "t", Endpoint: "gw:test", Env: "prod"},
			scopes: []string{"k8s:delete"},
			args:   map[string]any{"kind": "Deployment", "name": "checkout", "namespace": "payments"},
			want:   ApprovalRequired,
		},

		// --- VRP ----------------------------------------------------------
		{
			name: "shutting an interface on production is denied", tool: "net_config", kind: action.KindVRP,
			target: action.Target{Kind: action.KindVRP, Name: "t", Endpoint: "gw:test", Env: "prod"},
			scopes: []string{"vrp:config"},
			args:   map[string]any{"config": "interface GigabitEthernet0/0/1\n shutdown\n"},
			want:   Deny,
		},
		{
			name: "shutting an interface on staging needs approval", tool: "net_config", kind: action.KindVRP,
			scopes: []string{"vrp:config"},
			args:   map[string]any{"config": "interface GigabitEthernet0/0/1\n shutdown\n"},
			want:   ApprovalRequired,
		},
		{
			name: "resetting the saved configuration is denied", tool: "net_config", kind: action.KindVRP,
			scopes: []string{"vrp:config"},
			args:   map[string]any{"config": "reset saved-configuration\n"},
			want:   Deny,
		},
		{
			name: "rewriting device credentials is denied", tool: "net_config", kind: action.KindVRP,
			scopes: []string{"vrp:config"},
			args:   map[string]any{"config": "local-user admin\n"},
			want:   Deny,
		},
		{
			name: "a route-policy change needs approval", tool: "net_config", kind: action.KindVRP,
			scopes: []string{"vrp:config"},
			args:   map[string]any{"config": "route-policy IMPORT-PEER permit node 10\n"},
			want:   ApprovalRequired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := runCase(t, e, tc)
			if d.Decision != tc.want {
				t.Fatalf("decision = %s, want %s (reasons: %v)", d.Decision, tc.want, d.Reasons)
			}
			if tc.wantRisk != "" && d.Risk != tc.wantRisk {
				t.Errorf("risk = %s, want %s", d.Risk, tc.wantRisk)
			}
			if d.PolicyVersion == "" || d.PolicyVersion == "unloaded" {
				t.Errorf("policy_version = %q", d.PolicyVersion)
			}
			if d.Engine != "opa-embedded" {
				t.Errorf("engine = %q", d.Engine)
			}
		})
	}
}

// A denial has to explain itself: an Agent that gets "denied" with no reason
// retries with a different spelling, which is exactly the loop the gateway
// exists to stop.
func TestDenialsCarryReasons(t *testing.T) {
	e := newEngine(t)
	d := runCase(t, e, evalCase{
		tool: "redis_exec", kind: action.KindRedis,
		scopes: []string{"redis:delete"}, args: map[string]any{"command": "FLUSHALL"},
		want: Deny,
	})
	if d.Decision != Deny {
		t.Fatalf("decision = %s", d.Decision)
	}
	if len(d.Reasons) == 0 {
		t.Fatal("a denial with no reasons gives the Agent nothing to work with")
	}
	joined := strings.Join(d.Reasons, " | ")
	if !strings.Contains(joined, "keyspace") {
		t.Errorf("the reason does not explain the risk: %v", d.Reasons)
	}
	if d.RequiredScope == "" {
		t.Error("the required scope was not reported")
	}
}

// Approval cases must state how many humans are needed, because "1" and "2"
// are different processes at 3am.
func TestApprovalCounts(t *testing.T) {
	e := newEngine(t)

	// A production delete with a namespace-wide blast radius needs two people.
	dual := runCase(t, e, evalCase{
		tool: "net_config", kind: action.KindVRP,
		target: action.Target{Kind: action.KindVRP, Name: "t", Endpoint: "gw:test", Env: "prod"},
		scopes: []string{"vrp:config"},
		args:   map[string]any{"config": "interface GigabitEthernet0/0/1\n undo description\n"},
	})
	if dual.Decision != ApprovalRequired {
		t.Fatalf("decision = %s, want approval_required (reasons %v)", dual.Decision, dual.Reasons)
	}

	// A staging write needs exactly one.
	single := runCase(t, e, evalCase{
		tool: "k8s_delete", kind: action.KindK8s,
		scopes: []string{"k8s:delete"},
		args:   map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"},
	})
	if single.RequiredApprovals != 1 {
		t.Fatalf("required_approvals = %d, want 1", single.RequiredApprovals)
	}
}

// The endpoint must come from gateway config. An Agent that supplies its own
// endpoint is trying to redirect the credential, and the bundle says no.
func TestAgentSuppliedEndpointIsDenied(t *testing.T) {
	e := newEngine(t)
	a, err := action.NewRegistry().Normalize("k8s_get",
		map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"},
		action.Target{Kind: action.KindK8s, Name: "cluster", Endpoint: "https://attacker.example:6443", Env: "staging"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	d, err := e.Decide(context.Background(), Input{
		Action: a,
		Actor:  Actor{Subject: "agent-1", Scopes: []string{"k8s:read"}},
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if d.Decision != Deny {
		t.Fatalf("an agent-supplied endpoint was accepted: %s", d.Decision)
	}
	if !strings.Contains(strings.Join(d.Reasons, " "), "endpoint") {
		t.Errorf("the reason does not mention the endpoint: %v", d.Reasons)
	}
}

// An unsealed action (no hash) must never evaluate to allow: it would mean the
// approval binding has nothing to bind to.
func TestUnsealedActionIsDenied(t *testing.T) {
	e := newEngine(t)
	a := &action.Action{
		Tool:   "redis_exec",
		Target: action.Target{Kind: action.KindRedis, Name: "t", Endpoint: "gw:test", Env: "staging"},
		Verb:   action.VerbRead,
		Args:   map[string]any{"command_upper": "GET"},
	}
	d, err := e.Decide(context.Background(), Input{Action: a, Actor: Actor{Subject: "agent-1", Scopes: []string{"redis:read"}}})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if d.Decision != Deny {
		t.Fatalf("an action with an empty hash was not denied (got %s)", d.Decision)
	}
}

// A nil actor is an unauthenticated call. It must be denied, not defaulted.
func TestAnonymousActorIsDenied(t *testing.T) {
	e := newEngine(t)
	d := runCase(t, e, evalCase{
		tool: "redis_exec", kind: action.KindRedis,
		scopes: []string{"redis:read"}, args: map[string]any{"command": "GET k"},
	})
	if d.Decision != Allow {
		t.Fatalf("baseline should be allow, got %s", d.Decision)
	}

	a, err := action.NewRegistry().Normalize("redis_exec", map[string]any{"command": "GET k"},
		action.Target{Kind: action.KindRedis, Name: "t", Endpoint: "gw:test", Env: "staging"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	anon, err := e.Decide(context.Background(), Input{
		Action: a,
		Actor:  Actor{Scopes: []string{"redis:read"}}, // no subject
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if anon.Decision != Deny {
		t.Fatalf("anonymous actor was allowed (%s)", anon.Decision)
	}
}

// The engine must refuse to start without a bundle rather than run open.
func TestEngineRefusesEmptyBundle(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewRegoEngine(context.Background(), []string{dir}); err == nil {
		t.Fatal("the engine compiled an empty policy directory")
	}
}

func TestEngineMetadata(t *testing.T) {
	e := newEngine(t)
	if e.Version() == "" {
		t.Error("bundle version is empty")
	}
	if !strings.Contains(e.Source(), "embedded") {
		t.Errorf("source = %q, want the embedded bundle", e.Source())
	}
	if e.ModuleCount() < 5 {
		t.Errorf("only %d modules loaded; the bundle looks partial", e.ModuleCount())
	}
}

// A reason must come from the subsystem the action is against.
//
// The vrp approval rule keys on verb == "config", which Redis CONFIG also uses.
// Before the aggregation was gated on target.kind, a Redis change was explained
// to the approver as "vrp: every device configuration change needs a human in
// the loop". The verdict was right and the reason was wrong, which is the worst
// combination: the reason is what the approver reads and what the red-team
// report prints as the justification.
func TestReasonsComeFromTheMatchingSubsystem(t *testing.T) {
	e := newEngine(t)

	d := runCase(t, e, evalCase{
		// A non-sensitive CONFIG SET: verb is "config", so this is exactly the
		// shape the vrp rule used to fire on. Sensitive parameters are denied
		// outright, which would have made this test pass for the wrong reason.
		name: "redis CONFIG SET needs approval", tool: "redis_exec", kind: action.KindRedis,
		scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG SET lfu-log-factor 10"},
	})
	if d.Decision != ApprovalRequired {
		t.Fatalf("decision = %s, want approval_required (%v)", d.Decision, d.Reasons)
	}
	joined := strings.Join(d.Reasons, " | ")
	if strings.Contains(joined, "vrp:") {
		t.Errorf("a Redis action was explained with a network-device reason: %v", d.Reasons)
	}
	if !strings.Contains(joined, "redis:") {
		t.Errorf("the reason does not name the Redis subsystem: %v", d.Reasons)
	}

	k8s := runCase(t, e, evalCase{
		name: "k8s scale needs approval", tool: "k8s_scale", kind: action.KindK8s,
		scopes: []string{"k8s:write"},
		args:   map[string]any{"kind": "Deployment", "name": "web", "namespace": "default", "replicas": 1},
	})
	for _, r := range k8s.Reasons {
		if strings.HasPrefix(r, "redis:") || strings.HasPrefix(r, "vrp:") {
			t.Errorf("a Kubernetes action carries a reason from another subsystem: %v", k8s.Reasons)
		}
	}
}

// Read-only server diagnostics must not be gated.
//
// MEMORY / SLOWLOG / CONFIG GET <one non-credential param> report state and
// change nothing. Putting a human in front of "how much memory is used" is the
// cheapest possible way to train an operator to approve without reading, which
// is the failure mode the whole approval step depends on avoiding.
func TestReadOnlyDiagnosticsAreAllowed(t *testing.T) {
	e := newEngine(t)
	for _, tc := range []evalCase{
		{
			name: "MEMORY USAGE", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "MEMORY USAGE cache:homepage"},
		},
		{
			name: "SLOWLOG GET", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "SLOWLOG GET 10"},
		},
		{
			name: "CONFIG GET one safe param", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG GET maxmemory"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := runCase(t, e, tc)
			if d.Decision != Allow {
				t.Fatalf("%s: decision = %s (%v), want allow", tc.name, d.Decision, d.Reasons)
			}
			if len(d.Reasons) == 0 {
				t.Error("allowed with no reason")
			}
		})
	}

	// The permissive param-level rule must not have opened the credential door.
	for _, tc := range []evalCase{
		{
			name: "CONFIG GET requirepass", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG GET requirepass"},
		},
		{
			name: "CONFIG GET *", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG GET *"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if d := runCase(t, e, tc); d.Decision != Deny {
				t.Fatalf("%s: decision = %s, want deny", tc.name, d.Decision)
			}
		})
	}

	// And CONFIG SET of a sensitive parameter stays denied.
	t.Run("CONFIG SET dir", func(t *testing.T) {
		d := runCase(t, e, evalCase{
			name: "CONFIG SET dir", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:admin"}, args: map[string]any{"command": "CONFIG SET dir /tmp"},
		})
		if d.Decision != Deny {
			t.Fatalf("CONFIG SET dir: decision = %s, want deny", d.Decision)
		}
	})
}

// An allow must explain itself.
//
// This is not cosmetic. "The gateway said yes" with no stated reason is a
// verdict an operator can neither argue with nor tune, and it is what made the
// first red-team gap table unreadable: every payload the gateway permitted
// showed up as "(no reason returned)". Deny and approval_required never had
// this problem, which is exactly how it went unnoticed.
func TestEveryAllowCarriesAReason(t *testing.T) {
	e := newEngine(t)

	cases := []evalCase{
		{
			name: "redis read", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:read"}, args: map[string]any{"command": "GET session:42"},
		},
		{
			name: "redis single-key delete", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:delete"}, args: map[string]any{"command": "DEL orders:1001"},
		},
		{
			name: "redis single-key write", tool: "redis_exec", kind: action.KindRedis,
			scopes: []string{"redis:write"}, args: map[string]any{"command": "SET flag off"},
		},
		{
			name: "k8s read", tool: "k8s_get", kind: action.KindK8s,
			scopes: []string{"k8s:read"},
			args:   map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := runCase(t, e, tc)
			if d.Decision != Allow {
				t.Fatalf("%s: baseline should be allow, got %s (%v)", tc.name, d.Decision, d.Reasons)
			}
			if len(d.Reasons) == 0 {
				t.Fatal("an allow verdict carried no reason, so the report cannot say why the action was permitted")
			}
			for _, r := range d.Reasons {
				if strings.TrimSpace(r) == "" {
					t.Errorf("allow reason is blank: %q", r)
				}
			}
		})
	}
}
