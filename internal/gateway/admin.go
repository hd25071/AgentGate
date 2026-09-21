package gateway

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hd25071/AgentGate/internal/auth"
	"github.com/hd25071/AgentGate/internal/mcp"
	"github.com/hd25071/AgentGate/internal/store"
	"github.com/hd25071/AgentGate/internal/version"
	"github.com/hd25071/AgentGate/web"
)

// Routes builds the HTTP surface.
//
// Two audiences, two credentials. Agents present a scoped token at /mcp;
// humans present an admin token under /admin. An Agent token can never approve
// anything, which is the whole point of the separation: the thing that asks
// must not be the thing that says yes.
func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()

	// --- agent surface ---
	mux.Handle("/mcp", mcp.NewHTTPHandler(g.mcp, g.authenticateAgent, g.log))

	// --- unauthenticated probes ---
	mux.HandleFunc("GET /healthz", g.handleHealth)
	mux.HandleFunc("GET /readyz", g.handleReady)
	mux.HandleFunc("GET /metrics", g.handleMetrics)

	// --- admin surface ---
	mux.Handle("GET /admin/approvals", g.admin(g.handleListApprovals))
	mux.Handle("POST /admin/approvals/{id}/approve", g.admin(g.handleApprove))
	mux.Handle("POST /admin/approvals/{id}/reject", g.admin(g.handleReject))
	mux.Handle("GET /admin/approvals/{id}", g.admin(g.handleGetApproval))

	mux.Handle("GET /admin/audit", g.admin(g.handleAudit))
	mux.Handle("GET /admin/audit/verify", g.admin(g.handleVerifyChain))
	mux.Handle("GET /admin/replay/{id}", g.admin(g.handleReplay))
	mux.Handle("GET /admin/executions/{id}", g.admin(g.handleExecution))

	mux.Handle("GET /admin/policies", g.admin(g.handlePolicies))
	mux.Handle("GET /admin/tokens", g.admin(g.handleTokenHelp))
	mux.Handle("POST /admin/simulator/reseed", g.admin(g.handleReseedSimulator))

	// The UI shell is served without the admin wrapper, deliberately. A browser
	// navigating to /admin/ui has nowhere to put an X-Admin-Token header, so
	// wrapping the shell would 401 the page before the token input inside it
	// ever became reachable -- the page could never be used to do the one thing
	// it exists to do. The shell itself carries no data; it is a form that asks
	// for the token and then attaches it to every /admin/* call it makes, so
	// the boundary that matters is on those calls, not on the HTML.
	mux.HandleFunc("GET /admin/ui", serveUI)
	mux.HandleFunc("GET /admin/ui/replay/{id}", serveUI)

	// The catch-all is deliberately registered without a method. Go 1.22's
	// ServeMux rejects two patterns that each win on a different axis: "GET /"
	// is narrower on method than "/mcp" and broader on path, so neither is more
	// specific than the other and registration panics at startup. An
	// unconstrained "/" is strictly less specific than "/mcp" and therefore
	// legal. The handler still refuses anything that is not exactly "/".
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/admin/ui", http.StatusFound)
	})

	return mux
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

// authenticateAgent verifies the scoped token on an MCP request.
func (g *Gateway) authenticateAgent(ctx context.Context, r *http.Request) (mcp.Identity, error) {
	raw := r.Header.Get("Authorization")
	if raw == "" {
		raw = r.Header.Get("X-AgentGate-Token")
	}
	if raw == "" {
		// A session query parameter is accepted only for local stdio-style
		// debugging, never for a real deployment.
		return mcp.Identity{}, fmt.Errorf("missing bearer token")
	}
	claims, err := g.signer.Verify(raw)
	if err != nil {
		return mcp.Identity{}, fmt.Errorf("token rejected: %v", err)
	}
	return mcp.Identity{
		Subject: claims.Subject,
		Scopes:  claims.Scopes,
		Session: claims.Session,
		TokenID: claims.TokenID,
		Raw:     raw,
	}, nil
}

// admin wraps a handler with admin-token authentication.
//
// It fails closed on an unconfigured token. config.Load refuses to start
// without AG_ADMIN_TOKEN, but a Config assembled by another caller would
// otherwise compare two empty strings and report a match, which is the one
// way this check could silently become a no-op.
func (g *Gateway) admin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.cfg.AdminToken == "" {
			writeProblem(w, http.StatusServiceUnavailable, "admin surface is not configured",
				"the gateway has no admin token, so no admin request can be authenticated")
			return
		}
		got := r.Header.Get("X-Admin-Token")
		if got == "" {
			got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(g.cfg.AdminToken)) != 1 {
			writeProblem(w, http.StatusUnauthorized, "admin token required",
				"send X-Admin-Token or Authorization: Bearer <AG_ADMIN_TOKEN>")
			return
		}
		next(w, r)
	})
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"version":       version.String(),
		"uptime_s":      int(time.Since(g.startedAt).Seconds()),
		"policy":        g.policy.Version(),
		"policy_source": g.policy.Source(),
		"env":           g.cfg.Env(),
		"adapters":      g.adapters.HealthAll(r.Context()),
		"tools":         g.mcp.ToolNames(),
	})
}

func (g *Gateway) handleReady(w http.ResponseWriter, r *http.Request) {
	report, err := g.audit.Verify(r.Context())
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "audit chain unreadable", err.Error())
		return
	}
	if !report.Valid {
		writeProblem(w, http.StatusServiceUnavailable, "audit chain is broken", report.Reason)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "audit_chain_length": report.Length, "head": report.HeadHash})
}

func (g *Gateway) handleMetrics(w http.ResponseWriter, r *http.Request) {
	report, _ := g.audit.Verify(r.Context())
	approvals, _ := g.approval.List(r.Context(), store.StatusPending, 500)
	recs, _ := g.store.ListAudit(r.Context(), 100000)

	counts := map[string]int{}
	for _, rec := range recs {
		counts[rec.Type]++
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	b.WriteString("# HELP agentgate_audit_chain_length Records in the tamper-evident chain\n")
	b.WriteString("# TYPE agentgate_audit_chain_length gauge\n")
	fmt.Fprintf(&b, "agentgate_audit_chain_length %d\n", report.Length)
	b.WriteString("# HELP agentgate_audit_chain_valid 1 when the chain verifies\n")
	b.WriteString("# TYPE agentgate_audit_chain_valid gauge\n")
	fmt.Fprintf(&b, "agentgate_audit_chain_valid %d\n", boolToInt(report.Valid))
	b.WriteString("# HELP agentgate_approvals_pending Approvals waiting for a human\n")
	b.WriteString("# TYPE agentgate_approvals_pending gauge\n")
	fmt.Fprintf(&b, "agentgate_approvals_pending %d\n", len(approvals))
	b.WriteString("# HELP agentgate_events_total Audit events by type\n")
	b.WriteString("# TYPE agentgate_events_total counter\n")
	for _, t := range []string{
		store.EvPolicyDecision, store.EvApprovalRequest, store.EvApprovalGranted,
		store.EvApprovalRejected, store.EvExecuteResult, store.EvExecuteFailed,
		store.EvRollbackResult, store.EvAuthRejected,
	} {
		fmt.Fprintf(&b, "agentgate_events_total{type=%q} %d\n", t, counts[t])
	}
	if g.policy.Version() != "" {
		b.WriteString("# HELP agentgate_policy_info Loaded policy bundle\n")
		b.WriteString("# TYPE agentgate_policy_info gauge\n")
		fmt.Fprintf(&b, "agentgate_policy_info{version=%q} 1\n", g.policy.Version())
	}
	_, _ = w.Write([]byte(b.String()))
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

func (g *Gateway) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = store.StatusPending
	}
	limit := queryInt(r, "limit", 100)
	list, err := g.approval.List(r.Context(), status, limit)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "could not list approvals", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": list, "count": len(list)})
}

func (g *Gateway) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	ap, err := g.approval.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "approval not found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ap)
}

type voteBody struct {
	Actor      string `json:"actor"`
	ActionHash string `json:"action_hash"`
	Comment    string `json:"comment"`
}

func (g *Gateway) handleApprove(w http.ResponseWriter, r *http.Request) {
	g.vote(w, r, true)
}

func (g *Gateway) handleReject(w http.ResponseWriter, r *http.Request) {
	g.vote(w, r, false)
}

func (g *Gateway) vote(w http.ResponseWriter, r *http.Request, approve bool) {
	var body voteBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeProblem(w, http.StatusBadRequest, "request body must be JSON",
			`{"actor":"you","action_hash":"sha256:...","comment":"why"}`)
		return
	}
	ap, err := g.approval.Vote(r.Context(), r.PathValue("id"), body.Actor, approve, body.Comment, body.ActionHash)
	if err != nil {
		status := http.StatusConflict
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		if strings.Contains(err.Error(), "hash") {
			status = http.StatusPreconditionFailed
		}
		writeProblem(w, status, "vote rejected", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ap)
}

// ---------------------------------------------------------------------------
// Audit and replay
// ---------------------------------------------------------------------------

func (g *Gateway) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 200)
	recs, err := g.store.ListAudit(r.Context(), limit)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "could not read audit log", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": recs, "count": len(recs)})
}

func (g *Gateway) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	report, err := g.audit.Verify(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "chain verification failed", err.Error())
		return
	}
	status := http.StatusOK
	if !report.Valid {
		status = http.StatusConflict
	}
	writeJSON(w, status, report)
}

func (g *Gateway) handleReplay(w http.ResponseWriter, r *http.Request) {
	timeline, err := g.audit.Replay(r.Context(), r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "could not build the timeline", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, timeline)
}

func (g *Gateway) handleExecution(w http.ResponseWriter, r *http.Request) {
	ex, err := g.store.GetExecution(r.Context(), r.PathValue("id"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "execution not found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ex)
}

func (g *Gateway) handlePolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         g.policy.Version(),
		"source":          g.policy.Source(),
		"engine":          "embedded OPA (rego)",
		"decision_states": []string{"allow", "approval_required", "deny"},
		"note":            "deny is the default: an input shape no rule matches is denied, not allowed",
	})
}

func (g *Gateway) handleTokenHelp(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"scopes":     auth.KnownScopes(),
		"issue_with": "agentgate-cli token issue --subject <name> --scopes <a,b> --ttl 1h",
		"note":       "the gateway holds kubeconfig, Redis credentials and device credentials; agents hold only these scopes",
	})
}

// handleReseedSimulator puts the in-memory Kubernetes simulator back to its
// documented starting inventory.
//
// Only the red-team harness needs this, and only so that its numbers mean
// something: a payload that deletes a Deployment would otherwise succeed on the
// first repeat and report "not found" on the rest, and the guarded-execution
// rate would measure payload ordering instead of policy. It is refused on a
// cluster-mode gateway rather than being made a no-op, because the one thing
// worse than a harness that cannot reseed is a harness that believes it did.
func (g *Gateway) handleReseedSimulator(w http.ResponseWriter, r *http.Request) {
	if g.cfg.K8s.Mode != "mock" {
		writeProblem(w, http.StatusNotFound, "no simulator to reseed",
			fmt.Sprintf("the Kubernetes adapter is in %q mode; a real cluster cannot be restored to a checkpoint", g.cfg.K8s.Mode))
		return
	}
	if !g.adapters.ReseedSimulator() {
		writeProblem(w, http.StatusNotFound, "no simulator to reseed",
			"no in-memory Kubernetes adapter is registered")
		return
	}
	g.log.Info("simulator reseeded", "by", "admin-api")
	writeJSON(w, http.StatusOK, map[string]any{
		"reseeded": true,
		"note":     "the in-memory cluster is back to its seeded inventory; audit records are untouched",
	})
}

// serveUI serves the embedded approval and replay page.
func serveUI(w http.ResponseWriter, r *http.Request) {
	page, err := web.FS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "ui asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem emits an RFC 7807 style problem document.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, map[string]any{
		"type":   "about:blank",
		"title":  title,
		"status": status,
		"detail": detail,
	})
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	if n > 10000 {
		return 10000
	}
	return n
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
