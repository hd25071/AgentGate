// Package policy turns a normalized Action plus an authenticated actor into a
// three-state verdict.
//
// The engine is embedded OPA: policies/*.rego is compiled into the gateway
// binary at build time (go:embed) and can be overridden from disk for
// development. There is no network hop, no sidecar, and no way to run the
// gateway without a policy bundle loaded.
package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hd25071/AgentGate/internal/action"
)

// Verdict values. The set is deliberately three-valued: a boolean
// allow/deny forces every borderline case into "deny" and pushes operators to
// disable the gateway. An explicit approval state is what makes the thing
// usable in a real change-management process.
const (
	Allow            = "allow"
	ApprovalRequired = "approval_required"
	Deny             = "deny"
)

// Decision is the verdict returned by the engine.
type Decision struct {
	Decision          string   `json:"decision"`
	Risk              string   `json:"risk"`
	Reasons           []string `json:"reasons"`
	RequiredApprovals int      `json:"required_approvals"`
	Flags             []string `json:"flags"`
	RequiredScope     string   `json:"required_scope"`
	PolicyVersion     string   `json:"policy_version"`
	// Engine records which evaluator produced the verdict, for audit.
	Engine string `json:"engine"`
	// EvalError is non-empty when the engine failed and we failed closed.
	EvalError string `json:"eval_error,omitempty"`
}

// Allowed reports whether the action may proceed without human approval.
func (d Decision) Allowed() bool { return d.Decision == Allow }

// NeedsApproval reports whether the action is suspended pending approval.
func (d Decision) NeedsApproval() bool { return d.Decision == ApprovalRequired }

// Actor is the authenticated caller.
type Actor struct {
	Subject string   `json:"subject"`
	Scopes  []string `json:"scopes"`
	Session string   `json:"session,omitempty"`
}

// HasScope reports whether the actor holds a scope.
func (a Actor) HasScope(s string) bool {
	for _, have := range a.Scopes {
		if have == s || have == "*" {
			return true
		}
	}
	return false
}

// Input is everything the policy is allowed to consider.
type Input struct {
	Action  *action.Action
	Actor   Actor
	Context map[string]any
}

// Engine evaluates policy.
type Engine interface {
	Decide(ctx context.Context, in Input) (Decision, error)
	Version() string
	// Source describes where the loaded bundle came from, for audit and for
	// the /healthz payload.
	Source() string
}

// regoInput mirrors the document shape the .rego files index into.
type regoInput struct {
	Action  *action.Action `json:"action"`
	Actor   Actor          `json:"actor"`
	Context map[string]any `json:"context,omitempty"`
}

func buildInput(in Input) (map[string]any, error) {
	ri := regoInput{
		Action:  in.Action.SemanticCopy(),
		Actor:   in.Actor,
		Context: in.Context,
	}
	if ri.Actor.Scopes == nil {
		ri.Actor.Scopes = []string{}
	}
	raw, err := json.Marshal(ri)
	if err != nil {
		return nil, fmt.Errorf("marshal policy input: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("normalize policy input: %w", err)
	}
	return doc, nil
}
