package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/adapters"
	"github.com/hd25071/AgentGate/internal/auth"
	"github.com/hd25071/AgentGate/internal/config"
	"github.com/hd25071/AgentGate/internal/mcp"
	"github.com/hd25071/AgentGate/internal/policy"
	"github.com/hd25071/AgentGate/internal/preview"
	"github.com/hd25071/AgentGate/internal/store"
)

// These tests drive the whole pipeline against the in-memory cluster and a
// real SQLite file: normalize -> policy -> approval -> preview -> snapshot ->
// execute -> audit. The unit tests cover each stage in isolation; this is the
// only place that checks the stages are actually wired to each other.
type harness struct {
	t   *testing.T
	gw  *Gateway
	st  store.Store
	k8s *adapters.MockK8sAdapter
}

func newHarness(t *testing.T, env string) *harness {
	t.Helper()
	ctx := context.Background()

	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "gw.db")) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	st, err := store.OpenSQLite(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	engine, err := policy.NewRegoEngine(ctx, nil)
	if err != nil {
		t.Fatalf("policy engine: %v", err)
	}

	k8s := adapters.NewMockK8sAdapter(adapters.K8sConfig{Name: "k8s-sim", Env: env})
	reg := adapters.NewRegistry()
	reg.Register(k8s)

	cfg := &config.Config{
		ExecTimeout:       30 * time.Second,
		ApprovalTTL:       30 * time.Minute,
		RollbackOnFailure: true,
		AdminToken:        "test-admin-token-0123456789ab",
		Targets: map[action.Kind]action.Target{
			action.KindK8s:   {Kind: action.KindK8s, Name: "cluster-sim", Endpoint: "gw:k8s", Env: env},
			action.KindRedis: {Kind: action.KindRedis, Name: "redis-sim", Endpoint: "gw:redis", Env: env},
			action.KindVRP:   {Kind: action.KindVRP, Name: "edge-sim", Endpoint: "gw:vrp", Env: env},
		},
	}
	signer, err := auth.NewSigner([]byte("test-secret-value-0123456789"), "agentgate-test")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	gw, err := New(Deps{
		Config: cfg, Logger: slog.Default(), Store: st, Signer: signer,
		Policy: engine, Adapters: reg, NetGuard: preview.NewLocalNetGuard(),
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	return &harness{t: t, gw: gw, st: st, k8s: k8s}
}

func (h *harness) ctx(scopes ...string) context.Context {
	return mcp.WithIdentity(context.Background(), mcp.Identity{
		Subject: "agent-1", Scopes: scopes, Session: "ses-test",
	})
}

func (h *harness) call(ctx context.Context, tool string, kind action.Kind, args map[string]any) mcp.CallToolResult {
	h.t.Helper()
	return h.gw.Call(ctx, tool, kind, args)
}

func deployment(name, ns string) map[string]any {
	return map[string]any{"kind": "Deployment", "name": name, "namespace": ns}
}

// The happy path: a read is allowed, executed against the simulator, and the
// result carries the execution id and the action hash.
func TestPipelineAllowsAndExecutesARead(t *testing.T) {
	h := newHarness(t, "staging")
	ctx := h.ctx("k8s:read")

	res := h.call(ctx, "k8s_get", action.KindK8s, deployment("web", "default"))
	if res.IsError {
		t.Fatalf("a benign read was refused: %s", text(res))
	}
	if got := res.StructuredContent["status"]; got != "executed" {
		t.Fatalf("status = %v (text: %s)", got, text(res))
	}
	if res.StructuredContent["execution_id"] == "" || res.StructuredContent["execution_id"] == nil {
		t.Error("no execution id was returned")
	}
	if res.StructuredContent["action_hash"] == "" {
		t.Error("no action hash was returned")
	}
	if res.StructuredContent["risk"] != "low" {
		t.Errorf("risk = %v, want low", res.StructuredContent["risk"])
	}

	// The read really happened: the adapter returned the object.
	out, ok := res.StructuredContent["output"].(map[string]any)
	if !ok {
		t.Fatalf("expected the object as output, got %#v", res.StructuredContent["output"])
	}
	if out["kind"] != "Deployment" {
		t.Errorf("output looks wrong: %#v", out["kind"])
	}

	rep, err := h.st.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !rep.Valid || rep.Length == 0 {
		t.Fatalf("the pipeline did not write an intact audit trail: %+v", rep)
	}
}

// A denial must be a plain, readable tool result. The Agent needs the reason,
// and no approval row may be created: a denied action is not waiting for
// anything.
func TestPipelineDeniesWithoutQueueing(t *testing.T) {
	h := newHarness(t, "staging")
	ctx := h.ctx("k8s:delete")

	res := h.call(ctx, "k8s_delete", action.KindK8s, map[string]any{"kind": "Namespace", "name": "payments"})
	if !res.IsError {
		t.Fatalf("deleting a Namespace was allowed: %s", text(res))
	}
	if got := res.StructuredContent["status"]; got != "denied" {
		t.Fatalf("status = %v, want denied", got)
	}
	if !strings.Contains(text(res), "DENIED") {
		t.Errorf("the denial text does not tell the agent it was denied: %s", text(res))
	}
	// The message has to close the retry loop explicitly.
	if !strings.Contains(text(res), "action_hash=") {
		t.Errorf("the denial does not quote the action hash: %s", text(res))
	}

	approvals, err := h.gw.Approvals().List(ctx, "", 0)
	if err != nil {
		t.Fatalf("list approvals: %v", err)
	}
	if len(approvals) != 0 {
		t.Fatalf("a denied action was queued for approval (%d rows)", len(approvals))
	}

	// Nothing was deleted.
	for _, o := range h.k8s.Inventory() {
		if o == "namespace//payments" {
			return
		}
	}
	t.Fatal("the Namespace was deleted despite the policy denial")
}

// The full approval round trip, including the property that matters: the
// executor runs the action that was approved, and only that.
func TestPipelineApprovalRoundTrip(t *testing.T) {
	h := newHarness(t, "staging")
	ctx := h.ctx("k8s:delete")

	res := h.call(ctx, "k8s_delete", action.KindK8s, deployment("web", "default"))
	if res.IsError {
		t.Fatalf("the delete was denied instead of queued: %s", text(res))
	}
	if got := res.StructuredContent["status"]; got != "pending_approval" {
		t.Fatalf("status = %v, want pending_approval (%s)", got, text(res))
	}
	approvalID, _ := res.StructuredContent["approval_id"].(string)
	approvedHash, _ := res.StructuredContent["action_hash"].(string)
	if approvalID == "" || approvedHash == "" {
		t.Fatalf("the pending result is missing ids: %#v", res.StructuredContent)
	}
	if !strings.Contains(text(res), "Nothing has been executed") {
		t.Errorf("the pending text does not make clear that nothing ran: %s", text(res))
	}

	// The object must still be there: pending is not a euphemism for "ran".
	stillThere := false
	for _, o := range h.k8s.Inventory() {
		if o == "deployment/default/web" {
			stillThere = true
		}
	}
	if !stillThere {
		t.Fatal("the target was modified while the approval was pending")
	}

	// An approver who quotes the wrong hash is approving a different action.
	if _, err := h.gw.Approvals().Vote(ctx, approvalID, "ops@example.com", true, "lgtm", "sha256:0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("a vote quoting a different action hash was accepted")
	}
	// The requester cannot approve their own action.
	if _, err := h.gw.Approvals().Vote(ctx, approvalID, "agent-1", true, "self", approvedHash); err == nil {
		t.Fatal("self-approval was accepted")
	}

	ap, err := h.gw.Approvals().Vote(ctx, approvalID, "ops@example.com", true, "lgtm", approvedHash)
	if err != nil {
		t.Fatalf("vote: %v", err)
	}
	if ap.Status != store.StatusApproved {
		t.Fatalf("status after the vote = %s, want approved", ap.Status)
	}

	// The resumer runs asynchronously; wait for the execution to land.
	final := waitForApproval(t, h, approvalID)
	if final.Status != store.StatusExecuted {
		t.Fatalf("approval ended as %s (result: %s)", final.Status, final.ResultJSON)
	}
	if final.ExecutionID == "" {
		t.Error("the executed approval has no execution id")
	}
	if final.PreviewJSON == "" {
		t.Error("the approval did not record the preview that preceded execution")
	}
	if hint := final.RollbackHint(); hint == "" {
		t.Error("the approval recorded no rollback hint for the operator")
	}

	// The delete actually happened, and only after approval.
	gone := true
	for _, o := range h.k8s.Inventory() {
		if o == "deployment/default/web" {
			gone = false
		}
	}
	if !gone {
		t.Fatal("the approved delete did not take effect")
	}

	rep, err := h.st.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("the approval round trip broke the audit chain: %s", rep.Reason)
	}
}

func waitForApproval(t *testing.T, h *harness, id string) *store.Approval {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ap, err := h.st.GetApproval(context.Background(), id)
		if err != nil {
			t.Fatalf("get approval: %v", err)
		}
		if h.gw.Approvals().Settled(ap.Status) {
			return ap
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("approval %s never settled", id)
	return nil
}

// Production raises the bar without changing the shape of the response: a
// write that is allowed in staging comes back as an approval request here.
func TestProductionEscalatesWrites(t *testing.T) {
	h := newHarness(t, "prod")
	ctx := h.ctx("k8s:write")

	res := h.call(ctx, "k8s_apply", action.KindK8s, map[string]any{
		"kind": "Deployment", "name": "web", "namespace": "default",
		"manifest": map[string]any{
			"kind":     "Deployment",
			"metadata": map[string]any{"name": "web", "namespace": "default"},
		},
	})
	if res.IsError {
		t.Fatalf("unexpected refusal: %s", text(res))
	}
	if got := res.StructuredContent["status"]; got != "pending_approval" {
		t.Fatalf("status = %v, want pending_approval in production", got)
	}
}

// An unparseable call is refused before policy even runs. This is the shape an
// injection takes when it tries to smuggle a non-JSON manifest through.
func TestUnparseableCallIsRefused(t *testing.T) {
	h := newHarness(t, "staging")
	ctx := h.ctx("k8s:write")

	res := h.call(ctx, "k8s_apply", action.KindK8s, map[string]any{
		"kind": "Deployment", "name": "web", "namespace": "default",
		"manifest": "kind: Deployment\nmetadata:\n  name: web\n",
	})
	if !res.IsError {
		t.Fatalf("a YAML manifest was accepted: %s", text(res))
	}
	if got := res.StructuredContent["status"]; got != "denied" {
		t.Fatalf("status = %v, want denied", got)
	}
	if !strings.Contains(text(res), "could not parse") {
		t.Errorf("the refusal does not explain itself: %s", text(res))
	}
}

// Explain answers "would this be allowed?" without touching anything. That is
// the affordance that keeps an Agent from learning policy by trial and error.
func TestExplainDoesNotExecute(t *testing.T) {
	h := newHarness(t, "staging")
	ctx := h.ctx("k8s:delete")

	before := len(h.k8s.Inventory())
	res := h.gw.Explain(ctx, "k8s_delete", action.KindK8s, deployment("web", "default"))
	if res.IsError {
		t.Fatalf("explain failed: %s", text(res))
	}
	if got := res.StructuredContent["status"]; got != "explained" {
		t.Fatalf("status = %v, want explained", got)
	}
	if got := res.StructuredContent["decision"]; got != policy.ApprovalRequired {
		t.Fatalf("decision = %v, want approval_required", got)
	}
	if after := len(h.k8s.Inventory()); after != before {
		t.Fatal("Explain mutated the target")
	}

	// The hash Explain reports must be the hash the real call would use, or
	// the answer is worse than useless.
	real := h.call(ctx, "k8s_delete", action.KindK8s, deployment("web", "default"))
	if real.StructuredContent["action_hash"] != res.StructuredContent["action_hash"] {
		t.Fatalf("Explain hashed %v but the call hashed %v",
			res.StructuredContent["action_hash"], real.StructuredContent["action_hash"])
	}
}

// An authenticated call with no scope is denied: the token decides what an
// Agent may do, and "no scope" is not "all scopes".
func TestScopesAreEnforcedAcrossThePipeline(t *testing.T) {
	h := newHarness(t, "staging")

	res := h.call(h.ctx(), "k8s_get", action.KindK8s, deployment("web", "default"))
	if !res.IsError {
		t.Fatalf("a token with no scopes was allowed to read: %s", text(res))
	}
	if !strings.Contains(strings.Join(anyStrings(res.StructuredContent["reasons"]), " "), "scope") {
		t.Errorf("the denial does not mention the missing scope: %v", res.StructuredContent["reasons"])
	}

	// An unauthenticated context has no subject at all.
	bare := h.gw.Call(context.Background(), "k8s_get", action.KindK8s, deployment("web", "default"))
	if !bare.IsError {
		t.Fatalf("an unauthenticated call was allowed: %s", text(bare))
	}
}

// The MCP surface is what a host actually talks to, so one test goes through
// JSON-RPC rather than the Go API.
func TestMCPToolsCallEndToEnd(t *testing.T) {
	h := newHarness(t, "staging")
	srv := h.gw.MCPServer()

	names := srv.ToolNames()
	for _, want := range []string{"redis_exec", "k8s_get", "k8s_apply", "k8s_delete", "k8s_exec", "k8s_scale", "net_config", "agentgate_explain", "agentgate_approval_wait", "agentgate_approval_status"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("tool %q is not registered (registered: %v)", want, names)
		}
	}

	params, _ := json.Marshal(map[string]any{
		"name":      "k8s_get",
		"arguments": map[string]any{"kind": "Deployment", "name": "web", "namespace": "default"},
	})
	resp := srv.Handle(h.ctx("k8s:read"), &mcp.Request{
		JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params,
	})
	if resp == nil || resp.Error != nil {
		t.Fatalf("tools/call failed: %#v", resp)
	}
	result, ok := resp.Result.(mcp.CallToolResult)
	if !ok {
		t.Fatalf("unexpected result type %T", resp.Result)
	}
	if result.IsError {
		t.Fatalf("tools/call returned an error result: %s", text(result))
	}

	// An unknown tool is a protocol error, not a silent no-op.
	badParams, _ := json.Marshal(map[string]any{"name": "k8s_drain", "arguments": map[string]any{}})
	bad := srv.Handle(h.ctx("k8s:read"), &mcp.Request{
		JSONRPC: "2.0", ID: json.RawMessage(`2`), Method: "tools/call", Params: badParams,
	})
	if bad == nil || bad.Error == nil {
		t.Fatal("an unknown tool did not produce a JSON-RPC error")
	}
	if bad.Error.Code != mcp.CodeMethodNotFound {
		t.Errorf("error code = %d, want %d", bad.Error.Code, mcp.CodeMethodNotFound)
	}

	// initialize advertises the protocol version and the behavioural hint.
	init := srv.Handle(context.Background(), &mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`3`), Method: "initialize"})
	if init == nil || init.Error != nil {
		t.Fatalf("initialize failed: %#v", init)
	}
	ir, ok := init.Result.(mcp.InitializeResult)
	if !ok {
		t.Fatalf("initialize returned %T", init.Result)
	}
	if ir.Instructions == "" {
		t.Error("initialize returned no instructions for the host")
	}
}

// The HTTP surface has to be registered before anything can call it, and Go's
// ServeMux answers "is this registrable?" by panicking. That makes a startup
// crash the failure mode of a routing mistake, which the rest of the suite
// cannot see because nothing else touches Routes(). This test exists so that
// "the server comes up" is a property under test rather than a discovery made
// in production.
func TestRoutesMountWithoutConflicts(t *testing.T) {
	h := newHarness(t, "staging")
	rt := h.gw.Routes()
	if rt == nil {
		t.Fatal("Routes returned nil")
	}

	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusFound {
		t.Errorf("GET / = %d, want %d (a human should land on the approval UI)", rec.Code, http.StatusFound)
	}

	// An unrouted path is a 404, not a silent redirect to the UI.
	rec = httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /nope = %d, want 404", rec.Code)
	}

	// The liveness probe must answer without a token, or nothing can tell a
	// running gateway from a wedged one.
	rec = httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// The approval UI has to be reachable without a token, or there is nowhere
	// to type one -- a browser cannot attach an X-Admin-Token header to a page
	// navigation. The data behind it is a different matter, and both halves are
	// asserted here because either one alone is satisfied by a broken gateway:
	// an open shell over open data is a leak, and a gated shell over gated data
	// is a page nobody can open to approve anything.
	rec = httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/ui", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /admin/ui = %d, want 200 (the shell must load before a token can be entered)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "X-Admin-Token") {
		t.Error("the UI shell offers no way to enter the admin token")
	}

	for _, path := range []string{
		"/admin/approvals", "/admin/audit", "/admin/audit/verify",
		"/admin/policies", "/admin/tokens",
	} {
		rec = httptest.NewRecorder()
		rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401 without an admin token", path, rec.Code)
		}
	}

	// A wrong token is as good as no token.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/approvals", nil)
	req.Header.Set("X-Admin-Token", "not-the-admin-token")
	rt.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /admin/approvals with a wrong token = %d, want 401", rec.Code)
	}

	// The agent surface must refuse a request carrying no token. JSON-RPC
	// carries that refusal inside the envelope rather than in the HTTP status,
	// so the assertion is on the error, not on the status code: asserting 401
	// here would be asserting a transport detail the protocol does not use.
	rec = httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	body := rec.Body.String()
	if !strings.Contains(body, `"error"`) || strings.Contains(body, `"result"`) {
		t.Errorf("an unauthenticated tools/list was not refused: %s", body)
	}
	if !strings.Contains(body, "bearer token") {
		t.Errorf("the refusal does not say why: %s", body)
	}
}

// A gateway with no admin token must not authenticate anyone. config.Load
// rejects the empty value before a server can start, so this state is only
// reachable through a Config assembled by hand -- which is exactly what a later
// refactor or a new entry point tends to introduce, and exactly the case where
// comparing two empty strings would answer "match".
func TestAdminSurfaceFailsClosedWithoutAToken(t *testing.T) {
	h := newHarness(t, "staging")
	h.gw.cfg.AdminToken = ""
	rt := h.gw.Routes()

	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/approvals", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /admin/approvals with no configured admin token = %d, want 503 (body: %s)",
			rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/approvals", nil)
	req.Header.Set("X-Admin-Token", "")
	rt.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("an empty token authenticated an admin surface that has no token")
	}
}

func text(r mcp.CallToolResult) string {
	if len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].Text
}

func anyStrings(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, strings.TrimSpace(strings.Join([]string{stringify(e)}, "")))
		}
		return out
	default:
		return nil
	}
}

func stringify(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return strings.Trim(string(b), `"`)
}
