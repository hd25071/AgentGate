package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempDSN(t *testing.T) string {
	t.Helper()
	path := filepath.ToSlash(filepath.Join(t.TempDir(), "agentgate.db"))
	return "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
}

func openTestStore(t *testing.T) (Store, string) {
	t.Helper()
	dsn := tempDSN(t)
	st, err := OpenSQLite(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, dsn
}

// The audit chain is the artefact an incident review reads. Its one job is to
// make a silent edit detectable, so the test edits a record behind the
// store's back and checks that verification notices.
func TestAuditChainDetectsTampering(t *testing.T) {
	ctx := context.Background()
	st, dsn := openTestStore(t)

	for i, ev := range []string{EvRequestReceived, EvActionNormalized, EvPolicyDecision, EvExecuteResult} {
		rec, err := WriteAudit(ctx, st, "req-1", ev, map[string]any{"step": i})
		if err != nil {
			t.Fatalf("append %s: %v", ev, err)
		}
		if rec.Hash == "" || rec.Seq == 0 {
			t.Fatalf("appended record was not sealed: %+v", rec)
		}
		if i == 0 && rec.PrevHash != "" {
			t.Errorf("the genesis record should link to nothing, got %q", rec.PrevHash)
		}
	}

	rep, err := st.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("a freshly written chain failed verification: %s", rep.Reason)
	}
	if rep.Length != 4 {
		t.Fatalf("chain length = %d, want 4", rep.Length)
	}
	if rep.HeadHash == "" {
		t.Error("the chain head was not reported")
	}

	// Timeline for one request must come back in order.
	timeline, err := st.AuditByRequest(ctx, "req-1")
	if err != nil {
		t.Fatalf("audit by request: %v", err)
	}
	if len(timeline) != 4 {
		t.Fatalf("timeline has %d records, want 4", len(timeline))
	}
	for i := 1; i < len(timeline); i++ {
		if timeline[i].Seq < timeline[i-1].Seq {
			t.Fatalf("timeline is out of order at %d", i)
		}
		if timeline[i].PrevHash != timeline[i-1].Hash {
			t.Fatalf("record %d does not link to its predecessor", i)
		}
	}

	// Now edit a record the way an operator covering their tracks would.
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx,
		`UPDATE audit_records SET payload = ? WHERE seq = 2`, `{"step":"sanitised"}`); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	rep, err = st.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if rep.Valid {
		t.Fatal("an edited audit record went unnoticed")
	}
	if rep.BrokenAt != 2 {
		t.Fatalf("break reported at %d, want 2", rep.BrokenAt)
	}
	if !strings.Contains(rep.Reason, "does not match its hash") {
		t.Errorf("unhelpful break reason: %s", rep.Reason)
	}
}

// Deleting a record from the middle must break the *link*, not just the
// content hash, or a truncated log would still verify.
func TestAuditChainDetectsDeletion(t *testing.T) {
	ctx := context.Background()
	st, dsn := openTestStore(t)
	for i := 0; i < 3; i++ {
		if _, err := WriteAudit(ctx, st, "req-x", EvPolicyDecision, map[string]any{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer raw.Close()
	if _, err := raw.ExecContext(ctx, `DELETE FROM audit_records WHERE seq = 2`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rep, err := st.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Valid {
		t.Fatal("a deleted audit record went unnoticed")
	}
	if rep.BrokenAt != 3 {
		t.Fatalf("break reported at %d, want 3 (the record whose predecessor vanished)", rep.BrokenAt)
	}
}

func TestAppendAuditRequiresID(t *testing.T) {
	st, _ := openTestStore(t)
	if _, err := st.AppendAudit(context.Background(), AuditRecord{Type: EvRequestReceived}); err == nil {
		t.Fatal("a record with no id was appended")
	}
}

func TestListAuditIsOldestFirstAndLimited(t *testing.T) {
	ctx := context.Background()
	st, _ := openTestStore(t)
	for i := 0; i < 5; i++ {
		if _, err := WriteAudit(ctx, st, "req-1", EvExecuteResult, map[string]any{"i": i}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	all, err := st.ListAudit(ctx, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("got %d records, want 5", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].Seq <= all[i-1].Seq {
			t.Fatal("ListAudit did not return the timeline oldest-first")
		}
	}
	// "the last 2" has to mean the newest 2, rendered in order.
	last2, err := st.ListAudit(ctx, 2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(last2) != 2 {
		t.Fatalf("got %d records, want 2", len(last2))
	}
	if last2[0].Seq != 4 || last2[1].Seq != 5 {
		t.Fatalf("limit returned seqs %d,%d; want 4,5", last2[0].Seq, last2[1].Seq)
	}
}

func TestApprovalLifecycleAndExpiry(t *testing.T) {
	ctx := context.Background()
	st, _ := openTestStore(t)
	now := time.Now().UnixMilli()

	ap := &Approval{
		ID:           "apr-1",
		RequestID:    "req-1",
		Subject:      "agent-1",
		Tool:         "k8s_delete",
		Summary:      "k8s delete Deployment/web in default",
		ActionHash:   "sha256:deadbeef",
		ActionJSON:   `{"tool":"k8s_delete"}`,
		DecisionJSON: `{"decision":"approval_required"}`,
		Risk:         "high",
		Reasons:      []string{"k8s: deleting default/web"},
		Flags:        []string{},
		Required:     1,
		Status:       StatusPending,
		ExpiresAt:    now + int64(time.Hour/time.Millisecond),
	}
	if err := st.CreateApproval(ctx, ap); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := st.GetApproval(ctx, "apr-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusPending || got.Required != 1 {
		t.Fatalf("round-trip lost fields: %+v", got)
	}
	if len(got.Reasons) != 1 || len(got.Flags) != 0 || len(got.Approvals) != 0 {
		t.Fatalf("round-trip mangled the JSON columns: reasons=%v flags=%v votes=%v", got.Reasons, got.Flags, got.Approvals)
	}

	got.Approvals = append(got.Approvals, Vote{Actor: "ops@example.com", Approve: true, At: now, ActionHash: got.ActionHash})
	got.Status = StatusApproved
	got.DecisionNote = "approved by ops@example.com"
	if err := st.UpdateApproval(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, err := st.GetApproval(ctx, "apr-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if again.Status != StatusApproved || len(again.Approvals) != 1 || again.Approvals[0].Actor != "ops@example.com" {
		t.Fatalf("vote was not persisted: %+v", again)
	}

	// The queue must be filterable by status; the approver UI is built on it.
	pending, err := st.ListApprovals(ctx, StatusPending, 0)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("approved item still shows as pending (%d rows)", len(pending))
	}
	approved, err := st.ListApprovals(ctx, StatusApproved, 0)
	if err != nil {
		t.Fatalf("list approved: %v", err)
	}
	if len(approved) != 1 {
		t.Fatalf("got %d approved rows, want 1", len(approved))
	}

	// Expiry by deadline, not by wall clock at read time.
	stale := &Approval{
		ID: "apr-stale", RequestID: "req-2", Subject: "agent-2", Tool: "redis_exec",
		ActionHash: "sha256:cafe", Status: StatusPending, ExpiresAt: now - 1000,
	}
	if err := st.CreateApproval(ctx, stale); err != nil {
		t.Fatalf("create stale: %v", err)
	}
	n, err := st.ExpireStaleApprovals(ctx, time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired %d approvals, want 1", n)
	}
	expired, err := st.GetApproval(ctx, "apr-stale")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if expired.Status != StatusExpired {
		t.Fatalf("status = %s, want expired", expired.Status)
	}

	if _, err := st.GetApproval(ctx, "does-not-exist"); err == nil {
		t.Fatal("a missing approval did not produce an error")
	}
	if err := st.UpdateApproval(ctx, &Approval{ID: "does-not-exist"}); err == nil {
		t.Fatal("updating a missing approval did not produce an error")
	}
}

func TestExecutionIsUpserted(t *testing.T) {
	ctx := context.Background()
	st, _ := openTestStore(t)

	ex := &Execution{
		ID: "exec-1", RequestID: "req-1", ActionHash: "sha256:abc",
		Adapter: "k8s-sim", Status: "running", StartedAt: time.Now().UnixMilli(),
	}
	if err := st.SaveExecution(ctx, ex); err != nil {
		t.Fatalf("save start: %v", err)
	}
	// The executor writes the same row twice: once when it starts, once when
	// it finishes. A second insert must not collide.
	ex.Status = "ok"
	ex.ResultJSON = `{"summary":"deleted Deployment web"}`
	ex.FinishedAt = time.Now().UnixMilli()
	if err := st.SaveExecution(ctx, ex); err != nil {
		t.Fatalf("save finish: %v", err)
	}

	got, err := st.GetExecution(ctx, "exec-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != "ok" || got.FinishedAt == 0 {
		t.Fatalf("execution was not updated: %+v", got)
	}
	if err := st.SaveExecution(ctx, &Execution{RequestID: "req-1"}); err == nil {
		t.Fatal("an execution with no id was saved")
	}
}

// RollbackHint is what an approver reads to decide how much undo they get. An
// approval with no preview must say nothing rather than imply a clean undo.
func TestRollbackHint(t *testing.T) {
	if hint := (Approval{}).RollbackHint(); hint != "" {
		t.Errorf("an approval with no preview produced hint %q", hint)
	}

	preview, _ := json.Marshal(map[string]any{
		"rollback_note": "full object captured; rollback re-applies the captured manifest",
		"snapshot":      map[string]any{"strategy": "restore-object"},
	})
	if hint := (Approval{PreviewJSON: string(preview)}).RollbackHint(); !strings.Contains(hint, "full object captured") {
		t.Errorf("hint = %q", hint)
	}

	// Fall back to the snapshot note when only that is present.
	preview2, _ := json.Marshal(map[string]any{
		"snapshot": map[string]any{"strategy": "none", "note": "exec has no rollback: whatever the process did stands"},
	})
	if hint := (Approval{PreviewJSON: string(preview2)}).RollbackHint(); !strings.Contains(hint, "no rollback") {
		t.Errorf("hint = %q", hint)
	}

	if hint := (Approval{PreviewJSON: "{not json"}).RollbackHint(); hint != "" {
		t.Errorf("malformed preview produced hint %q", hint)
	}
}

// The sqlStore serializes appends so that a burst of concurrent writes still
// produces one unbroken chain.
func TestConcurrentAppendsKeepTheChainIntact(t *testing.T) {
	ctx := context.Background()
	st, _ := openTestStore(t)

	const n = 40
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			_, err := WriteAudit(ctx, st, "req-c", EvPolicyDecision, map[string]any{"i": i})
			errs <- err
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent append: %v", err)
		}
	}
	rep, err := st.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("concurrent appends broke the chain: %s", rep.Reason)
	}
	if rep.Length != n {
		t.Fatalf("chain length = %d, want %d", rep.Length, n)
	}
}
