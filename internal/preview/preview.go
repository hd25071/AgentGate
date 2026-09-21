// Package preview runs the non-mutating half of a change: the dry run and the
// impact analysis.
//
// Preview runs after approval and before execution, and its output -- together
// with the snapshot the same pass captures -- is what the approver sees and
// what the executor later relies on. Rolling the snapshot into preview is
// deliberate: "what will this do" and "can I take it back" are the same
// question to the person clicking approve.
package preview

import (
	"context"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/adapters"
)

// Outcome is everything the preview pass learned.
type Outcome struct {
	Supported    bool              `json:"supported"`
	Impact       string            `json:"impact"`
	Findings     []string          `json:"findings"`
	Details      any               `json:"details,omitempty"`
	Mode         string            `json:"mode,omitempty"`
	Snapshot     adapters.Snapshot `json:"snapshot"`
	RollbackNote string            `json:"rollback_note"`
	NetGuard     *Report           `json:"netguard,omitempty"`
	ElapsedMS    int64             `json:"elapsed_ms"`
	Error        string            `json:"error,omitempty"`
	PreviewedAt  int64             `json:"previewed_at"`
}

// Runner performs the preview pass.
type Runner struct {
	reg      *adapters.Registry
	netguard NetGuardClient
}

// New builds a Runner. A nil NetGuard client means network actions get a
// "no impact analysis available" finding instead of a silent pass.
func New(reg *adapters.Registry, ng NetGuardClient) *Runner {
	return &Runner{reg: reg, netguard: ng}
}

// Run previews one action.
func (r *Runner) Run(ctx context.Context, a *action.Action) Outcome {
	started := time.Now()
	out := Outcome{Findings: []string{}, PreviewedAt: started.UnixMilli()}

	ad, err := r.reg.Get(a.Target.Kind)
	if err != nil {
		out.Error = err.Error()
		out.RollbackNote = "adapter unavailable: no rollback material captured"
		out.ElapsedMS = time.Since(started).Milliseconds()
		return out
	}

	// 1. Dry run, where the target supports one.
	pv, err := ad.Preview(ctx, a)
	if err != nil {
		// A failing dry run is a finding, not a crash: the approver needs to
		// see it, and the executor will refuse to proceed.
		out.Error = "dry run failed: " + err.Error()
		out.Findings = append(out.Findings, "dry run failed: "+adapters.Redact(err.Error()))
		out.Impact = "dry run failed; the target rejected the change before any write"
		out.Mode = pv.Mode
	} else {
		out.Supported = pv.Supported
		out.Impact = pv.Impact
		out.Findings = append(out.Findings, pv.Findings...)
		out.Details = pv.Details
		out.Mode = pv.Mode
	}

	// 2. Snapshot, so the approver can judge whether the change is reversible.
	snap, serr := ad.Snapshot(ctx, a)
	if serr != nil {
		out.Snapshot = adapters.Snapshot{Adapter: ad.Name(), Strategy: "none", Note: "snapshot failed: " + serr.Error()}
		out.RollbackNote = "snapshot failed: " + adapters.Redact(serr.Error())
		out.Findings = append(out.Findings, "snapshot failed: "+adapters.Redact(serr.Error()))
	} else {
		out.Snapshot = snap
		out.RollbackNote = snap.Note
	}

	// 3. Network changes additionally get a reachability analysis.
	if a.Target.Kind == action.KindVRP && a.Verb != action.VerbRead {
		if r.netguard == nil {
			out.Findings = append(out.Findings, "no NetGuard endpoint configured: reachability impact was NOT analysed")
		} else {
			rep, nerr := r.netguard.Analyze(ctx, AnalyzeRequest{
				Device:      a.Target.Name,
				ConfigBlock: a.ArgString("config"),
				LineCount:   a.ArgInt("line_count"),
			})
			if nerr != nil {
				out.Findings = append(out.Findings, "NetGuard analysis failed: "+nerr.Error())
			} else {
				out.NetGuard = rep
				out.Findings = append(out.Findings, rep.Summary())
			}
		}
	}

	out.ElapsedMS = time.Since(started).Milliseconds()
	return out
}
