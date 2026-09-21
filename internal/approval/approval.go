// Package approval owns the human-in-the-loop step.
//
// The important property here is binding: an approval is a vote on a specific
// action hash, not on "a Redis deletion" or "whatever the Agent sends next".
// The hash covers every argument the normalizer extracted, so changing one byte
// after approval invalidates the vote and the action has to be re-approved.
// That closes the classic time-of-check/time-of-use gap between the review UI
// and the executor.
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/id"
	"github.com/hd25071/AgentGate/internal/policy"
	"github.com/hd25071/AgentGate/internal/store"
)

// Errors surfaced to approvers and to the waiting Agent.
var (
	ErrNotFound       = errors.New("approval not found")
	ErrNotPending     = errors.New("approval is no longer pending")
	ErrHashMismatch   = errors.New("approved hash does not match the stored action")
	ErrSelfApproval   = errors.New("the requesting subject cannot approve its own action")
	ErrDuplicateVote  = errors.New("this actor has already voted")
	ErrTimeout        = errors.New("timed out waiting for approval")
	ErrActionTampered = errors.New("stored action no longer matches its hash")
)

// Notifier delivers a pending-approval card to a human.
type Notifier interface {
	Notify(ctx context.Context, ap *store.Approval) error
	Name() string
}

// Resumer is invoked once an approval reaches the approved state. The gateway
// wires this to preview + execute; the approval package stays free of
// execution concerns so it can be tested without an adapter.
type Resumer func(ctx context.Context, ap *store.Approval)

// Manager is the approval queue.
type Manager struct {
	st       store.Store
	ttl      time.Duration
	notifier Notifier
	resumer  Resumer

	mu     sync.Mutex
	active map[string]bool
}

// Config tunes the manager.
type Config struct {
	TTL      time.Duration
	Notifier Notifier
}

// New builds a manager. A nil notifier means approvals only surface through the
// API and the web UI, which is a legitimate single-node setup.
func New(st store.Store, cfg Config) *Manager {
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if cfg.Notifier == nil {
		cfg.Notifier = LogNotifier{}
	}
	return &Manager{
		st:       st,
		ttl:      cfg.TTL,
		notifier: cfg.Notifier,
		active:   map[string]bool{},
	}
}

// SetResumer installs the post-approval hook.
func (m *Manager) SetResumer(r Resumer) { m.resumer = r }

// SubmitInput is what the gateway hands over when policy says "ask a human".
type SubmitInput struct {
	RequestID string
	Subject   string
	Action    *action.Action
	Decision  policy.Decision
}

// Submit records a pending approval and notifies approvers.
func (m *Manager) Submit(ctx context.Context, in SubmitInput) (*store.Approval, error) {
	actionJSON, err := json.Marshal(in.Action)
	if err != nil {
		return nil, fmt.Errorf("marshal action: %w", err)
	}
	decisionJSON, err := json.Marshal(in.Decision)
	if err != nil {
		return nil, fmt.Errorf("marshal decision: %w", err)
	}
	now := time.Now()
	required := in.Decision.RequiredApprovals
	if required <= 0 {
		required = 1
	}
	ap := &store.Approval{
		ID:           id.New("apr"),
		RequestID:    in.RequestID,
		Subject:      in.Subject,
		Tool:         in.Action.Tool,
		Summary:      in.Action.Summary(),
		ActionHash:   in.Action.Hash,
		ActionJSON:   string(actionJSON),
		DecisionJSON: string(decisionJSON),
		Risk:         in.Decision.Risk,
		Reasons:      in.Decision.Reasons,
		Flags:        in.Decision.Flags,
		Required:     required,
		Approvals:    []store.Vote{},
		Status:       store.StatusPending,
		CreatedAt:    now.UnixMilli(),
		ExpiresAt:    now.Add(m.ttl).UnixMilli(),
	}
	if err := m.st.CreateApproval(ctx, ap); err != nil {
		return nil, err
	}
	if err := m.notifier.Notify(ctx, ap); err != nil {
		// A failed notification must not swallow the approval: the queue is the
		// system of record, the notification is best effort.
		_, _ = store.WriteAudit(ctx, m.st, ap.RequestID, store.EvApprovalRequest, map[string]any{
			"approval_id":  ap.ID,
			"notify_error": err.Error(),
		})
	}
	return ap, nil
}

// Vote records an approver decision.
func (m *Manager) Vote(ctx context.Context, id, actor string, approve bool, comment, actionHash string) (*store.Approval, error) {
	ap, err := m.st.GetApproval(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if ap.Status != store.StatusPending {
		return nil, fmt.Errorf("%w: status is %s", ErrNotPending, ap.Status)
	}
	if time.Now().UnixMilli() > ap.ExpiresAt && ap.ExpiresAt > 0 {
		ap.Status = store.StatusExpired
		ap.DecisionNote = "deadline passed before a decision was recorded"
		_ = m.st.UpdateApproval(ctx, ap)
		return ap, fmt.Errorf("%w: deadline passed", ErrNotPending)
	}
	if strings.TrimSpace(actor) == "" {
		return nil, fmt.Errorf("approver identity is required")
	}
	if actor == ap.Subject {
		return nil, ErrSelfApproval
	}
	// Hash binding: the approver states which action they are approving, and it
	// has to be the one on file.
	if actionHash == "" {
		return nil, fmt.Errorf("%w: an approval must quote the action hash", ErrHashMismatch)
	}
	if normaliseHash(actionHash) != normaliseHash(ap.ActionHash) {
		return nil, fmt.Errorf("%w: approver saw %s but the queue holds %s",
			ErrHashMismatch, action.ShortHash(actionHash), action.ShortHash(ap.ActionHash))
	}
	for _, v := range ap.Approvals {
		if v.Actor == actor {
			return nil, ErrDuplicateVote
		}
	}

	ap.Approvals = append(ap.Approvals, store.Vote{
		Actor:      actor,
		Approve:    approve,
		Comment:    comment,
		At:         time.Now().UnixMilli(),
		ActionHash: ap.ActionHash,
	})

	switch {
	case !approve:
		ap.Status = store.StatusRejected
		ap.DecisionNote = fmt.Sprintf("rejected by %s", actor)
	case countApprovals(ap.Approvals) >= ap.Required:
		ap.Status = store.StatusApproved
		ap.DecisionNote = fmt.Sprintf("approved by %s", actor)
	default:
		ap.DecisionNote = fmt.Sprintf("%d of %d approvals collected", countApprovals(ap.Approvals), ap.Required)
	}

	if err := m.st.UpdateApproval(ctx, ap); err != nil {
		return nil, err
	}

	evt := store.EvApprovalGranted
	if !approve {
		evt = store.EvApprovalRejected
	}
	_, _ = store.WriteAudit(ctx, m.st, ap.RequestID, evt, map[string]any{
		"approval_id": ap.ID,
		"actor":       actor,
		"approve":     approve,
		"comment":     comment,
		"action_hash": ap.ActionHash,
		"status":      ap.Status,
	})

	if ap.Status == store.StatusApproved && m.resumer != nil {
		m.runResume(ap)
	}
	return ap, nil
}

// runResume executes the resume hook without blocking the approver's HTTP
// request, and without letting one slow execution pile up behind another for
// the same approval.
func (m *Manager) runResume(ap *store.Approval) {
	m.mu.Lock()
	if m.active[ap.ID] {
		m.mu.Unlock()
		return
	}
	m.active[ap.ID] = true
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.active, ap.ID)
			m.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		m.resumer(ctx, ap)
	}()
}

// Wait blocks until the approval leaves the pending state or the timeout
// elapses. Polling the store rather than using an in-memory channel keeps the
// wait correct when the approver is served by a different replica.
func (m *Manager) Wait(ctx context.Context, id string, timeout time.Duration) (*store.Approval, error) {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()

	for {
		ap, err := m.st.GetApproval(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		if ap.Status != store.StatusPending {
			return ap, nil
		}
		if time.Now().After(deadline) {
			return ap, ErrTimeout
		}
		select {
		case <-ctx.Done():
			return ap, ctx.Err()
		case <-ticker.C:
		}
	}
}

// Get fetches one approval.
func (m *Manager) Get(ctx context.Context, id string) (*store.Approval, error) {
	return m.st.GetApproval(ctx, id)
}

// List returns approvals, optionally filtered by status.
func (m *Manager) List(ctx context.Context, status string, limit int) ([]*store.Approval, error) {
	return m.st.ListApprovals(ctx, status, limit)
}

// ExpireSweep marks overdue pending approvals as expired. The gateway runs it
// on a ticker; it is also safe to call from a cron job.
func (m *Manager) ExpireSweep(ctx context.Context) (int, error) {
	n, err := m.st.ExpireStaleApprovals(ctx, time.Now().UnixMilli())
	if err != nil || n == 0 {
		return n, err
	}
	_, _ = store.WriteAudit(ctx, m.st, "", store.EvApprovalExpired, map[string]any{"count": n})
	return n, nil
}

// LoadAction decodes the stored action and re-verifies it against the stored
// hash. The executor calls this immediately before touching a target system.
func LoadAction(ap *store.Approval) (*action.Action, error) {
	var a action.Action
	if err := json.Unmarshal([]byte(ap.ActionJSON), &a); err != nil {
		return nil, fmt.Errorf("decode stored action: %w", err)
	}
	if err := a.VerifyHash(ap.ActionHash); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrActionTampered, err)
	}
	return &a, nil
}

func countApprovals(votes []store.Vote) int {
	n := 0
	for _, v := range votes {
		if v.Approve {
			n++
		}
	}
	return n
}

func normaliseHash(h string) string { return strings.TrimSpace(strings.ToLower(h)) }

// ---------------------------------------------------------------------------
// Notifiers
// ---------------------------------------------------------------------------

// LogNotifier records the card in the audit chain only. Default in dev.
type LogNotifier struct{}

func (LogNotifier) Name() string { return "log" }

func (LogNotifier) Notify(ctx context.Context, ap *store.Approval) error {
	return nil
}
