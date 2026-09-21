package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver
	_ "modernc.org/sqlite"             // pure-Go sqlite driver
)

// sqlStore implements Store over database/sql for both SQLite and PostgreSQL.
type sqlStore struct {
	db       *sql.DB
	dialect  string // "sqlite" | "postgres"
	appendMu sync.Mutex
}

// OpenSQLite opens (and creates) a SQLite database file.
func OpenSQLite(ctx context.Context, dsn string) (Store, error) {
	if dsn == "" {
		dsn = "file:agentgate.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite serializes writes anyway; one connection avoids SQLITE_BUSY churn.
	db.SetMaxOpenConns(1)
	s := &sqlStore{db: db, dialect: "sqlite"}
	if err := s.Init(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// OpenPostgres opens a PostgreSQL database.
func OpenPostgres(ctx context.Context, dsn string) (Store, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres store requires a DSN")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(16)
	s := &sqlStore{db: db, dialect: "postgres"}
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.Init(initCtx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Init creates the schema.
func (s *sqlStore) Init(ctx context.Context) error {
	for _, stmt := range schema(s.dialect) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("schema %q: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// Close releases the pool.
func (s *sqlStore) Close() error { return s.db.Close() }

// rebind converts the '?' placeholders used throughout this file into the
// $1..$n form PostgreSQL expects.
func (s *sqlStore) rebind(q string) string {
	if s.dialect != "postgres" {
		return q
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(q); i++ {
		if q[i] == '?' {
			n++
			b.WriteString("$")
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(q[i])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Audit chain
// ---------------------------------------------------------------------------

func chainHash(prev string, rec AuditRecord) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{0})
	h.Write([]byte(rec.ID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(rec.TS, 10)))
	h.Write([]byte{0})
	h.Write([]byte(rec.Type))
	h.Write([]byte{0})
	h.Write([]byte(rec.Payload))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// AppendAudit seals a record into the chain.
//
// The mutex serializes appends inside this process. Running multiple gateway
// replicas against one database would need a database-level lock; that is
// called out in docs/adr/0005-audit-chain.md rather than papered over.
func (s *sqlStore) AppendAudit(ctx context.Context, rec AuditRecord) (AuditRecord, error) {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	if rec.TS == 0 {
		rec.TS = time.Now().UnixMilli()
	}
	if rec.Payload == "" {
		rec.Payload = "{}"
	}
	if rec.ID == "" {
		return rec, fmt.Errorf("audit record requires an id")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return rec, err
	}
	defer func() { _ = tx.Rollback() }()

	var prev string
	row := tx.QueryRowContext(ctx, s.rebind(`SELECT hash FROM audit_records ORDER BY seq DESC LIMIT 1`))
	switch err := row.Scan(&prev); {
	case err == sql.ErrNoRows:
		prev = ""
	case err != nil:
		return rec, fmt.Errorf("read chain head: %w", err)
	}

	rec.PrevHash = prev
	rec.Hash = chainHash(prev, rec)

	if _, err := tx.ExecContext(ctx, s.rebind(
		`INSERT INTO audit_records (id, request_id, ts, type, payload, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		rec.ID, rec.RequestID, rec.TS, rec.Type, rec.Payload, rec.PrevHash, rec.Hash,
	); err != nil {
		return rec, fmt.Errorf("append audit: %w", err)
	}

	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT seq FROM audit_records WHERE id = ?`), rec.ID).Scan(&rec.Seq); err != nil {
		return rec, fmt.Errorf("read appended seq: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return rec, err
	}
	return rec, nil
}

func (s *sqlStore) AuditByRequest(ctx context.Context, requestID string) ([]AuditRecord, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(
		`SELECT seq, id, request_id, ts, type, payload, prev_hash, hash FROM audit_records WHERE request_id = ? ORDER BY seq ASC`),
		requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAudit(rows)
}

func (s *sqlStore) ListAudit(ctx context.Context, limit int) ([]AuditRecord, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(
		`SELECT seq, id, request_id, ts, type, payload, prev_hash, hash FROM audit_records ORDER BY seq DESC LIMIT ?`),
		limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanAudit(rows)
	if err != nil {
		return nil, err
	}
	// Return oldest-first so callers can render a timeline without reversing.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func scanAudit(rows *sql.Rows) ([]AuditRecord, error) {
	var out []AuditRecord
	for rows.Next() {
		var r AuditRecord
		if err := rows.Scan(&r.Seq, &r.ID, &r.RequestID, &r.TS, &r.Type, &r.Payload, &r.PrevHash, &r.Hash); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// VerifyChain walks the chain in seq order and recomputes every hash.
func (s *sqlStore) VerifyChain(ctx context.Context) (ChainReport, error) {
	rep := ChainReport{Valid: true, VerifiedAt: time.Now().UnixMilli()}
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, id, request_id, ts, type, payload, prev_hash, hash FROM audit_records ORDER BY seq ASC`)
	if err != nil {
		return rep, err
	}
	defer rows.Close()

	prev := ""
	var count int64
	for rows.Next() {
		var r AuditRecord
		if err := rows.Scan(&r.Seq, &r.ID, &r.RequestID, &r.TS, &r.Type, &r.Payload, &r.PrevHash, &r.Hash); err != nil {
			return rep, err
		}
		count++
		if r.PrevHash != prev {
			rep.Valid = false
			rep.BrokenAt = r.Seq
			rep.Reason = fmt.Sprintf("record %d links to %s but the previous record hashes to %s", r.Seq, short(r.PrevHash), short(prev))
			return rep, nil
		}
		want := chainHash(prev, r)
		if want != r.Hash {
			rep.Valid = false
			rep.BrokenAt = r.Seq
			rep.Reason = fmt.Sprintf("record %d content does not match its hash (stored %s, recomputed %s)", r.Seq, short(r.Hash), short(want))
			return rep, nil
		}
		prev = r.Hash
	}
	if err := rows.Err(); err != nil {
		return rep, err
	}
	rep.Length = count
	rep.HeadHash = prev
	return rep, nil
}

func short(h string) string {
	if h == "" {
		return "(genesis)"
	}
	if len(h) > 18 {
		return h[:18] + "..."
	}
	return h
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

func (s *sqlStore) CreateApproval(ctx context.Context, ap *Approval) error {
	if ap.ID == "" {
		return fmt.Errorf("approval requires an id")
	}
	if ap.CreatedAt == 0 {
		ap.CreatedAt = time.Now().UnixMilli()
	}
	ap.UpdatedAt = ap.CreatedAt
	_, err := s.db.ExecContext(ctx, s.rebind(
		`INSERT INTO approvals (id, request_id, subject, tool, summary, action_hash, action_json, decision_json,
		 risk, reasons, flags, required_approvals, approvals_json, status, created_at, updated_at, expires_at,
		 preview_json, result_json, execution_id, decision_note)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
		ap.ID, ap.RequestID, ap.Subject, ap.Tool, ap.Summary, ap.ActionHash, ap.ActionJSON, ap.DecisionJSON,
		ap.Risk, mustJSON(ap.Reasons), mustJSON(ap.Flags), ap.Required, mustJSON(ap.Approvals), ap.Status,
		ap.CreatedAt, ap.UpdatedAt, ap.ExpiresAt, ap.PreviewJSON, ap.ResultJSON, ap.ExecutionID, ap.DecisionNote,
	)
	if err != nil {
		return fmt.Errorf("create approval: %w", err)
	}
	return nil
}

const approvalCols = `id, request_id, subject, tool, summary, action_hash, action_json, decision_json,
	risk, reasons, flags, required_approvals, approvals_json, status, created_at, updated_at, expires_at,
	preview_json, result_json, execution_id, decision_note`

func (s *sqlStore) GetApproval(ctx context.Context, id string) (*Approval, error) {
	row := s.db.QueryRowContext(ctx, s.rebind(`SELECT `+approvalCols+` FROM approvals WHERE id = ?`), id)
	ap, err := scanApprovalRow(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("approval %s not found", id)
	}
	return ap, err
}

func (s *sqlStore) ListApprovals(ctx context.Context, status string, limit int) ([]*Approval, error) {
	if limit <= 0 {
		limit = 100
	}
	var (
		rows *sql.Rows
		err  error
	)
	if status == "" || status == "all" {
		rows, err = s.db.QueryContext(ctx, s.rebind(
			`SELECT `+approvalCols+` FROM approvals ORDER BY created_at DESC LIMIT ?`), limit)
	} else {
		rows, err = s.db.QueryContext(ctx, s.rebind(
			`SELECT `+approvalCols+` FROM approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?`), status, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Approval
	for rows.Next() {
		ap, err := scanApprovalRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ap)
	}
	return out, rows.Err()
}

func (s *sqlStore) UpdateApproval(ctx context.Context, ap *Approval) error {
	ap.UpdatedAt = time.Now().UnixMilli()
	res, err := s.db.ExecContext(ctx, s.rebind(
		`UPDATE approvals SET status = ?, approvals_json = ?, preview_json = ?, result_json = ?,
		 execution_id = ?, decision_note = ?, updated_at = ? WHERE id = ?`),
		ap.Status, mustJSON(ap.Approvals), ap.PreviewJSON, ap.ResultJSON,
		ap.ExecutionID, ap.DecisionNote, ap.UpdatedAt, ap.ID)
	if err != nil {
		return fmt.Errorf("update approval: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("approval %s not found", ap.ID)
	}
	return nil
}

func (s *sqlStore) ExpireStaleApprovals(ctx context.Context, now int64) (int, error) {
	res, err := s.db.ExecContext(ctx, s.rebind(
		`UPDATE approvals SET status = ?, updated_at = ?, decision_note = ? WHERE status = ? AND expires_at > 0 AND expires_at < ?`),
		StatusExpired, now, "auto-expired: nobody approved within the deadline", StatusPending, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanApprovalRow(sc scannable) (*Approval, error) {
	var (
		ap            Approval
		reasons       string
		flagsJSON     string
		approvalsJSON string
	)
	err := sc.Scan(&ap.ID, &ap.RequestID, &ap.Subject, &ap.Tool, &ap.Summary, &ap.ActionHash, &ap.ActionJSON,
		&ap.DecisionJSON, &ap.Risk, &reasons, &flagsJSON, &ap.Required, &approvalsJSON, &ap.Status,
		&ap.CreatedAt, &ap.UpdatedAt, &ap.ExpiresAt, &ap.PreviewJSON, &ap.ResultJSON, &ap.ExecutionID, &ap.DecisionNote)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(reasons), &ap.Reasons)
	_ = json.Unmarshal([]byte(flagsJSON), &ap.Flags)
	_ = json.Unmarshal([]byte(approvalsJSON), &ap.Approvals)
	if ap.Reasons == nil {
		ap.Reasons = []string{}
	}
	if ap.Flags == nil {
		ap.Flags = []string{}
	}
	if ap.Approvals == nil {
		ap.Approvals = []Vote{}
	}
	return &ap, nil
}

// ---------------------------------------------------------------------------
// Executions
// ---------------------------------------------------------------------------

func (s *sqlStore) SaveExecution(ctx context.Context, ex *Execution) error {
	if ex.ID == "" {
		return fmt.Errorf("execution requires an id")
	}
	if ex.StartedAt == 0 {
		ex.StartedAt = time.Now().UnixMilli()
	}
	_, err := s.db.ExecContext(ctx, s.rebind(
		`INSERT INTO executions (id, request_id, approval_id, action_hash, adapter, status, result_json,
		 snapshot_json, rollback_json, error, started_at, finished_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, result_json = EXCLUDED.result_json,
		 rollback_json = EXCLUDED.rollback_json, error = EXCLUDED.error, finished_at = EXCLUDED.finished_at`),
		ex.ID, ex.RequestID, ex.ApprovalID, ex.ActionHash, ex.Adapter, ex.Status, ex.ResultJSON,
		ex.SnapshotJSON, ex.RollbackJSON, ex.Error, ex.StartedAt, ex.FinishedAt)
	if err != nil {
		return fmt.Errorf("save execution: %w", err)
	}
	return nil
}

func (s *sqlStore) GetExecution(ctx context.Context, id string) (*Execution, error) {
	var ex Execution
	err := s.db.QueryRowContext(ctx, s.rebind(
		`SELECT id, request_id, approval_id, action_hash, adapter, status, result_json, snapshot_json,
		 rollback_json, error, started_at, finished_at FROM executions WHERE id = ?`), id).
		Scan(&ex.ID, &ex.RequestID, &ex.ApprovalID, &ex.ActionHash, &ex.Adapter, &ex.Status, &ex.ResultJSON,
			&ex.SnapshotJSON, &ex.RollbackJSON, &ex.Error, &ex.StartedAt, &ex.FinishedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("execution %s not found", id)
	}
	return &ex, err
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// WriteAudit is the convenience the gateway uses everywhere: marshal a payload
// and append it in one call.
func WriteAudit(ctx context.Context, st Store, requestID, evType string, payload any) (AuditRecord, error) {
	return st.AppendAudit(ctx, AuditRecord{
		ID:        newAuditID(),
		RequestID: requestID,
		TS:        time.Now().UnixMilli(),
		Type:      evType,
		Payload:   MarshalPayload(payload),
	})
}
