package adapters

import (
	"context"
	"strings"
	"testing"

	"github.com/hd25071/AgentGate/internal/action"
)

// ---------------------------------------------------------------------------
// Sanitize: the last line of defence before a target's reply enters the
// Agent's context window. Everything in that window is attacker-reachable
// through indirect injection, so a false negative here is a leaked credential.
// ---------------------------------------------------------------------------

func TestSanitizeRedactsSensitiveKeys(t *testing.T) {
	in := map[string]any{
		"username":    "orders",
		"password":    "hunter2hunter2",
		"nested":      map[string]any{"api_key": "sk-abcdefghijklmnop"},
		"list":        []any{"fine", "token=abcdef123456"},
		"description": "nothing to see here",
	}
	out, ok := Sanitize(in).(map[string]any)
	if !ok {
		t.Fatalf("Sanitize returned %T", Sanitize(in))
	}
	if out["password"] != "[REDACTED]" {
		t.Errorf("password = %v, want [REDACTED]", out["password"])
	}
	if out["username"] != "orders" {
		t.Errorf("a harmless key was altered: %v", out["username"])
	}
	if out["description"] != "nothing to see here" {
		t.Errorf("a harmless value was altered: %v", out["description"])
	}
	nested, _ := out["nested"].(map[string]any)
	if nested == nil || nested["api_key"] != "[REDACTED]" {
		t.Errorf("nested secret was not redacted: %#v", out["nested"])
	}
	list, _ := out["list"].([]any)
	if list == nil {
		t.Fatalf("list was not preserved: %#v", out["list"])
	}
	if list[0] != "fine" {
		t.Errorf("harmless list entry changed: %v", list[0])
	}
	if s, _ := list[1].(string); !strings.Contains(s, "REDACTED") {
		t.Errorf("a value containing a token marker was not redacted: %v", list[1])
	}
}

func TestSanitizeRedactsSensitiveValues(t *testing.T) {
	cases := []string{
		"requirepass: s3cret-value",
		"masterauth abcdef",
		"Bearer eyJhbGciOi",
		"-----BEGIN RSA PRIVATE KEY-----",
		"client_secret=xyz",
	}
	for _, c := range cases {
		got := sanitizeString(c)
		if !strings.Contains(got, "REDACTED") {
			t.Errorf("%q was not redacted (got %q)", c, got)
		}
	}
	// A long value keeps its shape so an operator can still see that something
	// was there; a short one is replaced entirely.
	if got := sanitizeString("password=abcdefghijkl"); !strings.HasPrefix(got, "pass") {
		t.Errorf("the redaction discarded the shape of a long value: %q", got)
	}
	if got := Redact("short"); got != "[REDACTED]" {
		t.Errorf("Redact(\"short\") = %q", got)
	}
}

func TestSanitizeHandlesResult(t *testing.T) {
	res := Result{
		Adapter: "redis", Status: "ok", Mutated: true,
		Summary: "CONFIG GET requirepass returned a value",
		Output:  map[string]any{"requirepass": "abc"},
	}
	out := Sanitize(res)
	got, ok := out.(Result)
	if !ok {
		t.Fatalf("Sanitize(Result) returned %T", out)
	}
	if !strings.Contains(got.Summary, "REDACTED") {
		t.Errorf("the summary was not sanitized: %q", got.Summary)
	}
	m, ok := got.Output.(map[string]any)
	if !ok || m["requirepass"] != "[REDACTED]" {
		t.Errorf("the output was not sanitized: %#v", got.Output)
	}
	if !got.Mutated {
		t.Error("Sanitize dropped the Mutated flag")
	}
}

func TestSanitizePassesThroughScalars(t *testing.T) {
	if got := Sanitize(42); got != 42 {
		t.Errorf("int changed: %v", got)
	}
	if got := Sanitize(nil); got != nil {
		t.Errorf("nil changed: %v", got)
	}
	if got := Sanitize(true); got != true {
		t.Errorf("bool changed: %v", got)
	}
}

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

func TestRegistryResolvesByKind(t *testing.T) {
	reg := NewRegistry()
	if _, err := reg.Get(action.KindK8s); err == nil {
		t.Fatal("an unregistered kind resolved")
	}
	k8s := NewMockK8sAdapter(K8sConfig{Name: "sim"})
	reg.Register(k8s)
	got, err := reg.Get(action.KindK8s)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name() != "sim" || got.Kind() != action.KindK8s {
		t.Fatalf("wrong adapter resolved: %s/%s", got.Name(), got.Kind())
	}
	if h := reg.HealthAll(context.Background()); h["k8s"] != "ok" {
		t.Errorf("health = %v", h)
	}
}

// ---------------------------------------------------------------------------
// Mock cluster: snapshot -> execute -> rollback
//
// The simulator is what the demo and the red-team harness run against, so its
// rollback has to actually work -- otherwise the pipeline's auto-rollback path
// is never exercised and nobody notices it is broken.
// ---------------------------------------------------------------------------

func normalizeK8s(t *testing.T, tool string, args map[string]any) *action.Action {
	t.Helper()
	a, err := action.NewRegistry().Normalize(tool, args,
		action.Target{Kind: action.KindK8s, Name: "sim", Endpoint: "gw:k8s", Env: "staging"})
	if err != nil {
		t.Fatalf("normalize %s: %v", tool, err)
	}
	return a
}

func contains(inv []string, want string) bool {
	for _, s := range inv {
		if s == want {
			return true
		}
	}
	return false
}

func TestMockK8sCreateAndRollback(t *testing.T) {
	ctx := context.Background()
	ad := NewMockK8sAdapter(K8sConfig{Name: "sim", Env: "staging"})

	a := normalizeK8s(t, "k8s_apply", map[string]any{
		"kind": "ConfigMap", "name": "brand-new", "namespace": "default",
		"manifest": map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "brand-new", "namespace": "default"},
		},
	})

	if contains(ad.Inventory(), "configmap/default/brand-new") {
		t.Fatal("the object already exists; the test is not testing creation")
	}

	snap, err := ad.Snapshot(ctx, a)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Strategy != "delete-on-rollback" {
		t.Fatalf("strategy = %q, want delete-on-rollback", snap.Strategy)
	}
	if snap.Note == "" {
		t.Error("the snapshot does not tell the approver what undo they get")
	}

	res, err := ad.Execute(ctx, a)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Mutated {
		t.Error("applying a new object did not report a mutation")
	}
	if !contains(ad.Inventory(), "configmap/default/brand-new") {
		t.Fatal("the object was not created")
	}

	if err := ad.Rollback(ctx, a, snap); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if contains(ad.Inventory(), "configmap/default/brand-new") {
		t.Fatal("rollback did not remove the created object")
	}
}

func TestMockK8sDeleteAndRollback(t *testing.T) {
	ctx := context.Background()
	ad := NewMockK8sAdapter(K8sConfig{Name: "sim", Env: "staging"})
	a := normalizeK8s(t, "k8s_delete", map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"})

	snap, err := ad.Snapshot(ctx, a)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Strategy != "restore-object" {
		t.Fatalf("strategy = %q, want restore-object", snap.Strategy)
	}
	if len(snap.Data) == 0 || string(snap.Data) == "{}" {
		t.Fatal("the snapshot captured no object data, so a rollback could not restore it")
	}

	if _, err := ad.Execute(ctx, a); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if contains(ad.Inventory(), "deployment/default/web") {
		t.Fatal("the delete did not take effect")
	}

	if err := ad.Rollback(ctx, a, snap); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !contains(ad.Inventory(), "deployment/default/web") {
		t.Fatal("rollback did not restore the deleted object")
	}
}

func TestMockK8sSnapshotForReadsAndExec(t *testing.T) {
	ctx := context.Background()
	ad := NewMockK8sAdapter(K8sConfig{Name: "sim", Env: "staging"})

	read := normalizeK8s(t, "k8s_get", map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"})
	snap, err := ad.Snapshot(ctx, read)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Strategy != "none" {
		t.Errorf("read snapshot strategy = %q, want none", snap.Strategy)
	}
	if !strings.Contains(snap.Note, "read-only") {
		t.Errorf("read snapshot note is unhelpful: %q", snap.Note)
	}
	if err := ad.Rollback(ctx, read, snap); err == nil {
		t.Error("rolling back a read-only snapshot should report that there is nothing to undo")
	}

	ex := normalizeK8s(t, "k8s_exec", map[string]any{
		"namespace": "payments", "pod": "checkout-1", "command": []any{"sh", "-c", "env"},
	})
	snap, err = ad.Snapshot(ctx, ex)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// exec must not pretend to be rollback-able: the process already ran.
	if !strings.Contains(snap.Note, "no rollback") {
		t.Errorf("exec snapshot claims more undo than it can deliver: %q", snap.Note)
	}
}

// A dry run the target rejects must surface as an error, because the pipeline
// treats a failed dry run as a hard stop.
func TestMockK8sPreviewFailsOnMissingObject(t *testing.T) {
	ctx := context.Background()
	ad := NewMockK8sAdapter(K8sConfig{Name: "sim"})
	a := normalizeK8s(t, "k8s_delete", map[string]any{"kind": "Deployment", "name": "ghost", "namespace": "default"})
	if _, err := ad.Preview(ctx, a); err == nil {
		t.Fatal("deleting a non-existent object passed its dry run")
	}
}

func TestMockK8sScalePreviewAndExecute(t *testing.T) {
	ctx := context.Background()
	ad := NewMockK8sAdapter(K8sConfig{Name: "sim"})
	a := normalizeK8s(t, "k8s_scale", map[string]any{"kind": "Deployment", "name": "web", "namespace": "default", "replicas": 7})

	pv, err := ad.Preview(ctx, a)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if !strings.Contains(pv.Impact, "3 -> 7") {
		t.Errorf("the preview does not show the before/after: %q", pv.Impact)
	}
	if _, err := ad.Execute(ctx, a); err != nil {
		t.Fatalf("execute: %v", err)
	}

	pv, err = ad.Preview(ctx, a)
	if err != nil {
		t.Fatalf("preview after scale: %v", err)
	}
	if !strings.Contains(pv.Impact, "7 -> 7") {
		t.Errorf("the seeded replica count was not updated: %q", pv.Impact)
	}
}

// The simulator reports its own nature. A preview that came from a mock must
// never be mistakable for one that came from a live cluster.
func TestMockK8sLabelsItself(t *testing.T) {
	ad := NewMockK8sAdapter(K8sConfig{Name: "k8s-simulator"})
	if ad.Name() != "k8s-simulator" {
		t.Errorf("adapter name = %q", ad.Name())
	}
	a := normalizeK8s(t, "k8s_apply", map[string]any{
		"kind": "Deployment", "name": "web", "namespace": "default",
		"manifest": map[string]any{
			"kind":     "Deployment",
			"metadata": map[string]any{"name": "web", "namespace": "default"},
		},
	})
	pv, err := ad.Preview(context.Background(), a)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	joined := strings.Join(pv.Findings, " | ")
	if !strings.Contains(joined, "simulator") {
		t.Errorf("the preview does not disclose that it is simulated: %v", pv.Findings)
	}
}

// The simulator must be internally consistent. A mock that knows about
// Deployments but not their Pods turns every pod-scoped action into "object not
// found", which is a failure of the simulator masquerading as a result of the
// test. The corpus, the demo and the exec path all name pods, so they have to
// exist.
func TestMockClusterSeedsTheObjectsTheCorpusNames(t *testing.T) {
	ad := NewMockK8sAdapter(K8sConfig{Name: "sim", Env: "staging"})
	for _, want := range []string{
		"deployment/default/web",
		"deployment/payments/checkout",
		"deployment/kube-system/coredns",
		"pod/default/web-7d9f8c6b4-x2k9m",
		"pod/payments/checkout-5c8d7f9b6-h3n8p",
		"pod/kube-system/coredns-6d4b75cb6-abcde",
		"statefulset/payments/orders-db",
		"namespace//payments",
	} {
		if !contains(ad.Inventory(), want) {
			t.Errorf("the simulator does not seed %s", want)
		}
	}
}

// Deleting the stuck pod the corpus names has to be a real delete against a
// real object: preview must resolve it, and the object must be gone afterwards.
func TestMockClusterCanDeleteTheTerminatingPod(t *testing.T) {
	ad := NewMockK8sAdapter(K8sConfig{Name: "sim", Env: "staging"})
	a := normalizeK8s(t, "k8s_delete", map[string]any{
		"kind": "Pod", "name": "web-7d9f8c6b4-x2k9m", "namespace": "default",
	})
	ctx := context.Background()

	pv, err := ad.Preview(ctx, a)
	if err != nil {
		t.Fatalf("preview of the seeded pod: %v", err)
	}
	if !strings.Contains(pv.Impact, "would be deleted") {
		t.Errorf("the preview did not describe the delete: %q", pv.Impact)
	}
	if _, err := ad.Snapshot(ctx, a); err != nil {
		t.Fatalf("snapshot of the seeded pod: %v", err)
	}
	res, err := ad.Execute(ctx, a)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Status != "ok" || !res.Mutated {
		t.Fatalf("delete of the seeded pod returned %s (mutated=%v)", res.Status, res.Mutated)
	}
	if contains(ad.Inventory(), "pod/default/web-7d9f8c6b4-x2k9m") {
		t.Fatal("the pod is still there after a successful delete")
	}
}
