// Package gateway wires the pipeline together.
//
// One tool call travels through exactly this path, and every arrow is an audit
// record:
//
//	MCP tools/call
//	  -> authenticate (scoped token; the gateway holds the real credentials)
//	  -> normalize     (raw arguments -> structured Action)
//	  -> policy        (allow / approval_required / deny, on the Action)
//	  -> approval      (suspend, bind to the action hash, collect human votes)
//	  -> preview       (dry run + reachability analysis + snapshot)
//	  -> execute       (perform, and roll back automatically on failure)
//	  -> sanitize      (strip anything credential-shaped)
//	  -> respond to the Agent
//
// The ordering matters. Policy runs on the normalized Action, not on the text,
// which is why casing tricks, command fragmenting and encoding tricks do not
// reach around the rules.
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/adapters"
	"github.com/hd25071/AgentGate/internal/approval"
	"github.com/hd25071/AgentGate/internal/audit"
	"github.com/hd25071/AgentGate/internal/auth"
	"github.com/hd25071/AgentGate/internal/config"
	"github.com/hd25071/AgentGate/internal/executor"
	"github.com/hd25071/AgentGate/internal/id"
	"github.com/hd25071/AgentGate/internal/mcp"
	"github.com/hd25071/AgentGate/internal/policy"
	"github.com/hd25071/AgentGate/internal/preview"
	"github.com/hd25071/AgentGate/internal/store"
	"github.com/hd25071/AgentGate/internal/version"
)

// Gateway is the assembled service.
type Gateway struct {
	cfg      *config.Config
	log      *slog.Logger
	store    store.Store
	audit    *audit.Recorder
	signer   *auth.Signer
	reg      *action.Registry
	policy   policy.Engine
	approval *approval.Manager
	preview  *preview.Runner
	exec     *executor.Executor
	adapters *adapters.Registry
	mcp      *mcp.Server

	startedAt time.Time
}

// Deps are the collaborators a Gateway needs.
type Deps struct {
	Config   *config.Config
	Logger   *slog.Logger
	Store    store.Store
	Signer   *auth.Signer
	Policy   policy.Engine
	Adapters *adapters.Registry
	NetGuard preview.NetGuardClient
}

// New assembles the gateway and registers its MCP tools.
func New(deps Deps) (*Gateway, error) {
	if deps.Config == nil || deps.Store == nil || deps.Policy == nil || deps.Adapters == nil {
		return nil, fmt.Errorf("gateway: config, store, policy and adapters are all required")
	}
	log := deps.Logger
	if log == nil {
		log = slog.Default()
	}

	approvals := approval.New(deps.Store, approval.Config{
		TTL:      deps.Config.ApprovalTTL,
		Notifier: notifierFor(deps.Config),
	})

	g := &Gateway{
		cfg:       deps.Config,
		log:       log,
		store:     deps.Store,
		audit:     audit.New(deps.Store, log),
		signer:    deps.Signer,
		reg:       action.NewRegistry(),
		policy:    deps.Policy,
		approval:  approvals,
		preview:   preview.New(deps.Adapters, deps.NetGuard),
		exec:      executor.New(deps.Adapters, deps.Store, log),
		adapters:  deps.Adapters,
		mcp:       mcp.NewServer("agentgate", version.Version),
		startedAt: time.Now(),
	}
	g.exec.RollbackOnFailure = deps.Config.RollbackOnFailure
	approvals.SetResumer(g.resumeApproved)
	g.registerTools()

	g.mcp.SetInstructions(
		"You are talking to AgentGate, an execution gateway for production operations. " +
			"Every tool call is normalized into a structured Action, checked against policy, and either allowed, " +
			"denied, or suspended for human approval. If a call returns pending_approval, poll " +
			"agentgate_approval_wait with the returned approval_id. Do not retry a denied call with different " +
			"spelling, casing or encoding: the gateway normalizes before deciding, and a retry of the same action " +
			"will be denied again.",
	)
	return g, nil
}

func notifierFor(cfg *config.Config) approval.Notifier {
	if cfg.ApprovalWebhookURL == "" {
		return approval.LogNotifier{}
	}
	return approval.NewWebhookNotifier(cfg.ApprovalWebhookURL, cfg.ApprovalWebhookShape)
}

// MCPServer exposes the MCP server so the transports can be mounted.
func (g *Gateway) MCPServer() *mcp.Server { return g.mcp }

// Signer exposes the token signer.
func (g *Gateway) Signer() *auth.Signer { return g.signer }

// Policy exposes the policy engine for the admin API.
func (g *Gateway) Policy() policy.Engine { return g.policy }

// Approvals exposes the approval manager.
func (g *Gateway) Approvals() *approval.Manager { return g.approval }

// Audit exposes the audit recorder.
func (g *Gateway) Audit() *audit.Recorder { return g.audit }

// Store exposes the store.
func (g *Gateway) Store() store.Store { return g.store }

// Adapters exposes the adapter registry.
func (g *Gateway) Adapters() *adapters.Registry { return g.adapters }

// StartedAt reports process start time.
func (g *Gateway) StartedAt() time.Time { return g.startedAt }

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

// Call runs one action-producing tool call through the full pipeline.
func (g *Gateway) Call(ctx context.Context, tool string, kind action.Kind, args map[string]any) mcp.CallToolResult {
	requestID := id.New("req")
	ident, _ := mcp.IdentityFrom(ctx)

	ctx, span := g.audit.Start(ctx, requestID, "agentgate.mcp."+tool)
	defer span.End()

	g.audit.MustRecord(ctx, requestID, store.EvRequestReceived, map[string]any{
		"tool":        tool,
		"subject":     ident.Subject,
		"session":     ident.Session,
		"args_digest": digestArgs(args),
		"remote_note": "raw arguments are deliberately not logged; only a digest",
	})

	target, ok := g.cfg.Targets[kind]
	if !ok {
		g.audit.MustRecord(ctx, requestID, store.EvAuthRejected, map[string]any{"reason": "no configured target"})
		return mcp.ErrorResult(fmt.Sprintf("no target is configured for kind %q", kind), map[string]any{
			"status": "denied", "reason": "no configured target",
		})
	}

	// 1. Normalize.
	a, err := g.reg.Normalize(tool, args, target)
	if err != nil {
		g.audit.MustRecord(ctx, requestID, store.EvActionNormalized, map[string]any{
			"ok": false, "error": err.Error(),
		})
		return mcp.ErrorResult(
			fmt.Sprintf("the gateway could not parse this call into a verifiable action, so it was refused: %v", err),
			map[string]any{"status": "denied", "reason": "unparseable action", "detail": err.Error()})
	}
	g.audit.MustRecord(ctx, requestID, store.EvActionNormalized, map[string]any{
		"ok": true, "action": a,
	})

	// 2. Decide.
	decision, err := g.policy.Decide(ctx, policy.Input{
		Action: a,
		Actor:  actorOf(ident),
		Context: map[string]any{
			"request_id": requestID,
			"tool":       tool,
			"env":        g.cfg.Env(),
			"policy":     g.policy.Version(),
		},
	})
	g.audit.MustRecord(ctx, requestID, store.EvPolicyDecision, map[string]any{
		"decision":    decision,
		"action_hash": a.Hash,
		"eval_error":  decision.EvalError,
	})
	if err != nil {
		g.log.Error("policy evaluation error", "request_id", requestID, "err", err)
	}

	switch decision.Decision {
	case policy.Deny:
		audit.Fail(span, fmt.Errorf("denied by policy"))
		return mcp.ErrorResult(
			fmt.Sprintf("DENIED by policy.\n%s\n\nThis is a decision on the normalized action, not on how you wrote it; "+
				"rewording, re-casing or splitting the request will land on the same rule. action_hash=%s",
				bulletList(decision.Reasons), a.Hash),
			map[string]any{
				"status":         "denied",
				"decision":       decision.Decision,
				"risk":           decision.Risk,
				"reasons":        decision.Reasons,
				"flags":          decision.Flags,
				"action_hash":    a.Hash,
				"action":         a,
				"policy_version": decision.PolicyVersion,
			})

	case policy.ApprovalRequired:
		ap, aerr := g.approval.Submit(ctx, approval.SubmitInput{
			RequestID: requestID,
			Subject:   ident.Subject,
			Action:    a,
			Decision:  decision,
		})
		if aerr != nil {
			g.log.Error("could not enqueue approval", "request_id", requestID, "err", aerr)
			return mcp.ErrorResult("the action needs approval but the approval queue rejected it; nothing was executed",
				map[string]any{"status": "failed", "reason": aerr.Error()})
		}
		g.audit.MustRecord(ctx, requestID, store.EvApprovalRequest, map[string]any{
			"approval_id": ap.ID,
			"action_hash": ap.ActionHash,
			"risk":        ap.Risk,
			"required":    ap.Required,
			"expires_at":  ap.ExpiresAt,
		})
		return mcp.TextResult(
			fmt.Sprintf("PENDING APPROVAL. Nothing has been executed.\n"+
				"approval_id=%s\nrequired_approvals=%d\naction_hash=%s\nreasons:\n%s\n\n"+
				"Poll agentgate_approval_wait with this approval_id. An approver must quote action_hash %s; "+
				"if any argument changes, a new approval is required.",
				ap.ID, ap.Required, ap.ActionHash, bulletList(decision.Reasons), ap.ActionHash),
			map[string]any{
				"status":             "pending_approval",
				"approval_id":        ap.ID,
				"action_hash":        ap.ActionHash,
				"risk":               ap.Risk,
				"reasons":            decision.Reasons,
				"flags":              decision.Flags,
				"required_approvals": ap.Required,
				"expires_at":         ap.ExpiresAt,
				"action":             a,
			})

	default:
		res, _ := g.execute(ctx, requestID, "", a, decision)
		return res
	}
}

// execute is the tail of the pipeline: preview, snapshot, run, record.
//
// The preview outcome is returned so the caller can persist the dry run that
// actually preceded this execution -- the approval record should show what was
// true at the moment of execution, not what was true an hour earlier.
func (g *Gateway) execute(ctx context.Context, requestID, approvalID string, a *action.Action,
	decision policy.Decision) (mcp.CallToolResult, *preview.Outcome) {

	ctx, cancel := context.WithTimeout(ctx, g.cfg.ExecTimeout)
	defer cancel()

	pv := g.preview.Run(ctx, a)
	g.audit.MustRecord(ctx, requestID, store.EvPreviewResult, pv)
	snap := pv.Snapshot

	if pv.Error != "" {
		// A dry run the target rejected is a hard stop: the change is known
		// bad, so there is nothing to execute.
		return mcp.ErrorResult(
			fmt.Sprintf("the dry run failed, so nothing was executed: %s", pv.Error),
			map[string]any{
				"status": "denied", "reason": "dry run failed",
				"impact": pv.Impact, "findings": pv.Findings, "action_hash": a.Hash,
			}), &pv
	}

	out, err := g.exec.Execute(ctx, executor.Request{
		RequestID:  requestID,
		ApprovalID: approvalID,
		Action:     a,
		Snapshot:   snap,
	})
	if err != nil {
		return mcp.ErrorResult(
			fmt.Sprintf("execution failed: %s", err.Error()),
			map[string]any{
				"status": "failed", "execution_id": out.ExecutionID, "error": err.Error(),
				"rolled_back": out.RolledBack, "rollback_error": out.RollbackError,
				"action_hash": a.Hash,
			}), &pv
	}

	structured := map[string]any{
		"status":       "executed",
		"execution_id": out.ExecutionID,
		"adapter":      out.Result.Adapter,
		"mutated":      out.Result.Mutated,
		"output":       out.Result.Output,
		"action_hash":  a.Hash,
		"decision":     decision.Decision,
		"risk":         decision.Risk,
		"rollback":     snap.Strategy,
	}
	return mcp.TextResult(fmt.Sprintf("%s\nexecution_id=%s action_hash=%s rollback=%s",
		out.Result.Summary, out.ExecutionID, action.ShortHash(a.Hash), snap.Strategy), structured), &pv
}

// resumeApproved runs after the last required approval lands.
//
// Note what is *not* here: the original arguments. The action is re-read from
// storage and re-verified against the approved hash, so the thing that executes
// is provably the thing that was reviewed.
func (g *Gateway) resumeApproved(ctx context.Context, ap *store.Approval) {
	log := g.log.With("approval_id", ap.ID, "request_id", ap.RequestID)

	a, err := approval.LoadAction(ap)
	if err != nil {
		log.Error("approved action failed its integrity check; refusing to execute", "err", err)
		ap.Status = store.StatusFailed
		ap.ResultJSON = store.MarshalPayload(map[string]any{"error": err.Error()})
		_ = g.store.UpdateApproval(ctx, ap)
		_, _ = g.audit.Record(ctx, ap.RequestID, store.EvExecuteFailed, map[string]any{
			"approval_id": ap.ID, "reason": err.Error(), "note": "action hash mismatch at resume time",
		})
		return
	}

	var decision policy.Decision
	_ = json.Unmarshal([]byte(ap.DecisionJSON), &decision)

	res, pv := g.execute(ctx, ap.RequestID, ap.ID, a, decision)

	raw, _ := json.Marshal(res.StructuredContent)
	ap.ResultJSON = string(raw)
	if res.IsError {
		ap.Status = store.StatusFailed
	} else {
		ap.Status = store.StatusExecuted
	}
	if v, ok := res.StructuredContent["execution_id"].(string); ok {
		ap.ExecutionID = v
	}
	// Keep the preview and the rollback material alongside the approval, so an
	// operator can undo the change later without digging through executions.
	if pv != nil {
		if b, err := json.Marshal(pv); err == nil {
			ap.PreviewJSON = string(b)
		}
	}
	if err := g.store.UpdateApproval(ctx, ap); err != nil {
		log.Error("could not persist approval outcome", "err", err)
	}
}

// Explain runs normalization and policy without executing anything. It exists
// so an agent (or a human debugging an agent) can ask "would this be allowed?"
// and get the same answer the real call would get.
func (g *Gateway) Explain(ctx context.Context, tool string, kind action.Kind, args map[string]any) mcp.CallToolResult {
	requestID := id.New("req")
	ident, _ := mcp.IdentityFrom(ctx)

	target, ok := g.cfg.Targets[kind]
	if !ok {
		return mcp.ErrorResult(fmt.Sprintf("no target configured for kind %q", kind), nil)
	}
	a, err := g.reg.Normalize(tool, args, target)
	if err != nil {
		return mcp.ErrorResult("the call could not be normalized: "+err.Error(),
			map[string]any{"status": "denied", "reason": "unparseable action"})
	}
	d, _ := g.policy.Decide(ctx, policy.Input{Action: a, Actor: actorOf(ident)})
	g.audit.MustRecord(ctx, requestID, store.EvPolicyDecision, map[string]any{
		"decision": d, "action_hash": a.Hash, "explain_only": true,
	})
	return mcp.TextResult(
		fmt.Sprintf("EXPLAIN (nothing executed)\nnormalized: %s\ndecision: %s (risk=%s, scope=%s)\naction_hash=%s\n%s",
			a.Summary(), d.Decision, d.Risk, d.RequiredScope, a.Hash, bulletList(d.Reasons)),
		map[string]any{
			"status": "explained", "decision": d.Decision, "risk": d.Risk, "reasons": d.Reasons,
			"flags": d.Flags, "required_scope": d.RequiredScope, "required_approvals": d.RequiredApprovals,
			"action_hash": a.Hash, "action": a, "policy_version": d.PolicyVersion,
		})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// actorOf projects the authenticated MCP identity onto the shape the policy
// engine reasons about.
//
// The projection is one-way on purpose: internal/mcp must not import
// internal/policy, or the transport layer would start depending on the
// decision layer and it would become possible to answer "who is this?" with
// something that was influenced by a policy outcome. Identity first, authority
// second.
func actorOf(ident mcp.Identity) policy.Actor {
	return policy.Actor{
		Subject: ident.Subject,
		Scopes:  append([]string(nil), ident.Scopes...),
		Session: ident.Session,
	}
}

// digestArgs hashes the raw argument object. The gateway logs the digest, not
// the arguments: an injected log line that reaches an agent's tool call is
// exactly the content we do not want copied into an audit database.
func digestArgs(args map[string]any) string {
	raw, err := json.Marshal(args)
	if err != nil {
		return "unhashable"
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:8])
}

// rawJSON embeds an already-encoded JSON document as data rather than as a
// quoted string, so an MCP client receives the object it expects instead of a
// stringified blob. Invalid JSON degrades to the original string: a broken
// stored payload must still render on the audit surface.
func rawJSON(s string) any {
	if s == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	return v
}

func bulletList(items []string) string {
	if len(items) == 0 {
		return "  (no reasons recorded)"
	}
	var b strings.Builder
	for _, it := range items {
		b.WriteString("  - ")
		b.WriteString(it)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
