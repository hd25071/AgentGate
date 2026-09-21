// Package store is the persistence layer: the tamper-evident audit log, the
// approval queue and the execution/snapshot records.
//
// Two drivers are supported behind one interface. SQLite (pure Go, no cgo) is
// the development default because it makes `docker compose up` a one-liner;
// PostgreSQL is what the interface is shaped for.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Audit event types. Kept as constants so the replay UI and the eval harness
// agree on names.
const (
	EvRequestReceived  = "request.received"
	EvAuthVerified     = "auth.verified"
	EvAuthRejected     = "auth.rejected"
	EvActionNormalized = "action.normalized"
	EvPolicyDecision   = "policy.decision"
	EvApprovalRequest  = "approval.requested"
	EvApprovalGranted  = "approval.granted"
	EvApprovalRejected = "approval.rejected"
	EvApprovalExpired  = "approval.expired"
	EvPreviewResult    = "preview.result"
	EvExecuteStarted   = "execute.started"
	EvExecuteResult    = "execute.result"
	EvExecuteFailed    = "execute.failed"
	EvRollbackResult   = "rollback.result"
	EvResponseReturned = "response.returned"
)

// AuditRecord is one link in the hash chain.
//
// Hash covers the previous hash, the identity and the payload, so removing or
// editing any record invalidates every record after it. The chain does not
// prevent an operator with database access from rewriting history from scratch;
// it makes silent edits detectable, which is what an audit trail is for.
type AuditRecord struct {
	Seq       int64  `json:"seq"`
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	TS        int64  `json:"ts"` // unix milliseconds
	Type      string `json:"type"`
	Payload   string `json:"payload"` // JSON
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// Time renders the record timestamp.
func (r AuditRecord) Time() time.Time { return time.UnixMilli(r.TS).UTC() }

// RollbackHint renders how much undo a human is actually getting, taken from
// the preview that ran alongside this approval. An approval with no preview
// returns "" rather than implying that a clean rollback exists: "we captured
// a full object" and "best effort" are different promises to an approver.
func (ap Approval) RollbackHint() string {
	if ap.PreviewJSON == "" {
		return ""
	}
	var pv struct {
		RollbackNote string `json:"rollback_note"`
		Snapshot     struct {
			Strategy string `json:"strategy"`
			Note     string `json:"note"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal([]byte(ap.PreviewJSON), &pv); err != nil {
		return ""
	}
	if pv.RollbackNote != "" {
		return pv.RollbackNote
	}
	return pv.Snapshot.Note
}

// Approval is a suspended high-risk action.
type Approval struct {
	ID           string   `json:"id"`
	RequestID    string   `json:"request_id"`
	Subject      string   `json:"subject"`
	Tool         string   `json:"tool"`
	Summary      string   `json:"summary"`
	ActionHash   string   `json:"action_hash"`
	ActionJSON   string   `json:"action_json"`
	DecisionJSON string   `json:"decision_json"`
	Risk         string   `json:"risk"`
	Reasons      []string `json:"reasons"`
	Flags        []string `json:"flags"`
	Required     int      `json:"required_approvals"`
	Approvals    []Vote   `json:"approvals"`
	Status       string   `json:"status"`
	CreatedAt    int64    `json:"created_at"`
	UpdatedAt    int64    `json:"updated_at"`
	ExpiresAt    int64    `json:"expires_at"`
	PreviewJSON  string   `json:"preview_json,omitempty"`
	ResultJSON   string   `json:"result_json,omitempty"`
	ExecutionID  string   `json:"execution_id,omitempty"`
	DecisionNote string   `json:"decision_note,omitempty"`
}

// Vote is one approver's decision.
type Vote struct {
	Actor      string `json:"actor"`
	Approve    bool   `json:"approve"`
	Comment    string `json:"comment,omitempty"`
	At         int64  `json:"at"`
	ActionHash string `json:"action_hash"`
}

// Approval statuses.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusExpired  = "expired"
	StatusExecuted = "executed"
	StatusFailed   = "failed"
)

// Execution is the record of one adapter invocation.
type Execution struct {
	ID           string `json:"id"`
	RequestID    string `json:"request_id"`
	ApprovalID   string `json:"approval_id,omitempty"`
	ActionHash   string `json:"action_hash"`
	Adapter      string `json:"adapter"`
	Status       string `json:"status"`
	ResultJSON   string `json:"result_json,omitempty"`
	SnapshotJSON string `json:"snapshot_json,omitempty"`
	RollbackJSON string `json:"rollback_json,omitempty"`
	Error        string `json:"error,omitempty"`
	StartedAt    int64  `json:"started_at"`
	FinishedAt   int64  `json:"finished_at"`
}

// Store is the persistence contract.
type Store interface {
	// Init creates the schema if needed.
	Init(ctx context.Context) error

	// AppendAudit seals a record into the hash chain and returns it with Seq,
	// PrevHash and Hash populated.
	AppendAudit(ctx context.Context, rec AuditRecord) (AuditRecord, error)

	// AuditByRequest returns the full timeline for one request id, ordered.
	AuditByRequest(ctx context.Context, requestID string) ([]AuditRecord, error)

	// ListAudit returns the most recent records, newest last.
	ListAudit(ctx context.Context, limit int) ([]AuditRecord, error)

	// VerifyChain recomputes the whole chain and reports the first break.
	VerifyChain(ctx context.Context) (ChainReport, error)

	CreateApproval(ctx context.Context, ap *Approval) error
	GetApproval(ctx context.Context, id string) (*Approval, error)
	ListApprovals(ctx context.Context, status string, limit int) ([]*Approval, error)
	UpdateApproval(ctx context.Context, ap *Approval) error
	// ExpireStaleApprovals marks pending approvals past their deadline.
	ExpireStaleApprovals(ctx context.Context, now int64) (int, error)

	SaveExecution(ctx context.Context, ex *Execution) error
	GetExecution(ctx context.Context, id string) (*Execution, error)

	Close() error
}

// ChainReport is the result of a chain verification.
type ChainReport struct {
	Valid      bool   `json:"valid"`
	Length     int64  `json:"length"`
	BrokenAt   int64  `json:"broken_at,omitempty"`
	Reason     string `json:"reason,omitempty"`
	HeadHash   string `json:"head_hash"`
	VerifiedAt int64  `json:"verified_at"`
}

// Open builds a Store from a driver name and DSN.
func Open(ctx context.Context, driver, dsn string) (Store, error) {
	switch driver {
	case "", "sqlite", "sqlite3":
		return OpenSQLite(ctx, dsn)
	case "postgres", "postgresql", "pgx":
		return OpenPostgres(ctx, dsn)
	default:
		return nil, fmt.Errorf("unknown store driver %q (want sqlite or postgres)", driver)
	}
}

// MarshalPayload is a small helper that keeps nil payloads out of the chain.
func MarshalPayload(v any) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"marshal_error":%q}`, err.Error())
	}
	return string(b)
}
