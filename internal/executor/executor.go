// Package executor performs the write step.
//
// Everything before this point is advice. The executor is where an action
// actually reaches a production system, so it re-checks the one invariant that
// matters -- that the Action in hand still hashes to the value that was
// approved -- and it records what it did before and after.
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/adapters"
	"github.com/hd25071/AgentGate/internal/id"
	"github.com/hd25071/AgentGate/internal/store"
)

// Executor runs approved actions.
type Executor struct {
	reg *adapters.Registry
	st  store.Store
	log *slog.Logger
	// RollbackOnFailure attempts an automatic undo when execution fails.
	RollbackOnFailure bool
}

// New builds an Executor.
func New(reg *adapters.Registry, st store.Store, log *slog.Logger) *Executor {
	if log == nil {
		log = slog.Default()
	}
	return &Executor{reg: reg, st: st, log: log, RollbackOnFailure: true}
}

// Request is one execution.
type Request struct {
	RequestID  string
	ApprovalID string
	Action     *action.Action
	Snapshot   adapters.Snapshot
}

// Outcome reports what happened.
type Outcome struct {
	ExecutionID   string          `json:"execution_id"`
	Status        string          `json:"status"`
	Result        adapters.Result `json:"result"`
	RolledBack    bool            `json:"rolled_back"`
	RollbackError string          `json:"rollback_error,omitempty"`
	StartedAt     int64           `json:"started_at"`
	FinishedAt    int64           `json:"finished_at"`
	Error         string          `json:"error,omitempty"`
}

// Execute validates, runs and records one action.
func (e *Executor) Execute(ctx context.Context, req Request) (Outcome, error) {
	started := time.Now()
	out := Outcome{
		ExecutionID: id.New("exec"),
		Status:      "running",
		StartedAt:   started.UnixMilli(),
	}

	if req.Action == nil {
		out.Status = store.StatusFailed
		out.Error = "no action supplied"
		return out, fmt.Errorf("executor: no action supplied")
	}

	// Invariant check, immediately before the side effect. If the action was
	// decoded from storage and no longer matches the approved hash, we stop.
	if err := req.Action.VerifyHash(req.Action.Hash); err != nil {
		out.Status = store.StatusFailed
		out.Error = "action integrity check failed: " + err.Error()
		_, _ = store.WriteAudit(ctx, e.st, req.RequestID, store.EvExecuteFailed, map[string]any{
			"execution_id": out.ExecutionID,
			"reason":       out.Error,
		})
		return out, fmt.Errorf("%w: %v", action.ErrHashMismatch, err)
	}

	ad, err := e.reg.Get(req.Action.Target.Kind)
	if err != nil {
		out.Status = store.StatusFailed
		out.Error = err.Error()
		return out, err
	}

	exec := &store.Execution{
		ID:         out.ExecutionID,
		RequestID:  req.RequestID,
		ApprovalID: req.ApprovalID,
		ActionHash: req.Action.Hash,
		Adapter:    ad.Name(),
		Status:     "running",
		StartedAt:  started.UnixMilli(),
	}
	if snapRaw, err := json.Marshal(req.Snapshot); err == nil {
		exec.SnapshotJSON = string(snapRaw)
	}
	if err := e.st.SaveExecution(ctx, exec); err != nil {
		e.log.Warn("could not persist execution start", "err", err)
	}

	_, _ = store.WriteAudit(ctx, e.st, req.RequestID, store.EvExecuteStarted, map[string]any{
		"execution_id": out.ExecutionID,
		"adapter":      ad.Name(),
		"summary":      req.Action.Summary(),
		"action_hash":  req.Action.Hash,
		"rollback":     req.Snapshot.Strategy,
	})

	res, execErr := ad.Execute(ctx, req.Action)
	out.Result = res
	out.FinishedAt = time.Now().UnixMilli()

	if execErr != nil {
		out.Status = store.StatusFailed
		out.Error = execErr.Error()
		_, _ = store.WriteAudit(ctx, e.st, req.RequestID, store.EvExecuteFailed, map[string]any{
			"execution_id": out.ExecutionID,
			"error":        adapters.Redact(execErr.Error()),
			"adapter":      ad.Name(),
		})
		if e.RollbackOnFailure && rollbackable(req.Snapshot) {
			if rbErr := ad.Rollback(ctx, req.Action, req.Snapshot); rbErr != nil {
				out.RollbackError = rbErr.Error()
				_, _ = store.WriteAudit(ctx, e.st, req.RequestID, store.EvRollbackResult, map[string]any{
					"execution_id": out.ExecutionID,
					"ok":           false,
					"error":        adapters.Redact(rbErr.Error()),
				})
			} else {
				out.RolledBack = true
				_, _ = store.WriteAudit(ctx, e.st, req.RequestID, store.EvRollbackResult, map[string]any{
					"execution_id": out.ExecutionID,
					"ok":           true,
					"strategy":     req.Snapshot.Strategy,
					"reason":       "automatic rollback after a failed execution",
				})
			}
		}
		e.persist(ctx, exec, out, nil)
		return out, execErr
	}

	out.Status = "ok"
	_, _ = store.WriteAudit(ctx, e.st, req.RequestID, store.EvExecuteResult, map[string]any{
		"execution_id": out.ExecutionID,
		"adapter":      ad.Name(),
		"status":       res.Status,
		"summary":      res.Summary,
		"mutated":      res.Mutated,
		"output":       adapters.Sanitize(res.Output),
		"duration_ms":  out.FinishedAt - out.StartedAt,
	})

	// A result that claims success but reports a write is worth persisting in
	// full: it is the artefact an incident review reads.
	execRes := map[string]any{
		"summary": res.Summary,
		"status":  res.Status,
		"output":  adapters.Sanitize(res.Output),
	}
	e.persist(ctx, exec, out, execRes)
	return out, nil
}

// Rollback is the manual, operator-initiated undo used by the CLI.
func (e *Executor) Rollback(ctx context.Context, requestID string, a *action.Action, snap adapters.Snapshot) error {
	ad, err := e.reg.Get(a.Target.Kind)
	if err != nil {
		return err
	}
	if err := ad.Rollback(ctx, a, snap); err != nil {
		_, _ = store.WriteAudit(ctx, e.st, requestID, store.EvRollbackResult, map[string]any{
			"ok":    false,
			"error": adapters.Redact(err.Error()),
		})
		return err
	}
	_, _ = store.WriteAudit(ctx, e.st, requestID, store.EvRollbackResult, map[string]any{
		"ok":       true,
		"strategy": snap.Strategy,
		"reason":   "manual rollback requested by an operator",
	})
	return nil
}

func (e *Executor) persist(ctx context.Context, exec *store.Execution, out Outcome, result map[string]any) {
	exec.Status = out.Status
	exec.FinishedAt = out.FinishedAt
	exec.Error = out.Error
	if result != nil {
		if raw, err := json.Marshal(result); err == nil {
			exec.ResultJSON = string(raw)
		}
	}
	if out.RolledBack {
		if raw, err := json.Marshal(map[string]any{"rolled_back": true, "error": out.RollbackError}); err == nil {
			exec.RollbackJSON = string(raw)
		}
	}
	if err := e.st.SaveExecution(ctx, exec); err != nil {
		e.log.Warn("could not persist execution result", "err", err)
	}
}

// rollbackable reports whether a snapshot carries enough to attempt an undo.
func rollbackable(s adapters.Snapshot) bool {
	if s.Strategy == "" || s.Strategy == "none" {
		return false
	}
	if len(s.Data) == 0 || string(s.Data) == "{}" {
		return false
	}
	return true
}
