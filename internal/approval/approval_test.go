package approval

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hd25071/AgentGate/internal/action"
	"github.com/hd25071/AgentGate/internal/policy"
	"github.com/hd25071/AgentGate/internal/store"
)

func testManager(t *testing.T, resumer Resumer) *Manager {
	t.Helper()
	path := filepath.ToSlash(filepath.Join(t.TempDir(), "agentgate.db"))
	st, err := store.OpenSQLite(context.Background(),
		"file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	m := New(st, Config{TTL: time.Minute})
	if resumer != nil {
		m.SetResumer(resumer)
	}
	return m
}

// Submit a redis action and return the approval the gateway would have queued.
func submit(t *testing.T, m *Manager, command string) (*store.Approval, *action.Action) {
	t.Helper()
	a, err := action.RedisNormalizer{}.Normalize(
		map[string]any{"command": command},
		action.Target{Kind: action.KindRedis, Name: "redis-1", Env: "staging"},
	)
	if err != nil {
		t.Fatalf("normalize %q: %v", command, err)
	}
	ap, err := m.Submit(context.Background(), SubmitInput{
		RequestID: "req-1",
		Subject:   "agent-1",
		Action:    a,
		Decision:  policy.Decision{Decision: policy.ApprovalRequired, Risk: "high", Reasons: []string{"test"}},
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return ap, a
}

// An approval is not finished when the vote is recorded. The action executes
// afterwards, and a caller waiting on the record has to be told which of the
// two it is looking at: "approved" is a decision, not an outcome.
func TestWaitReturnsOnlyAfterTheOutcomeLands(t *testing.T) {
	ctx := context.Background()
	var m *Manager
	m = testManager(t, func(ctx context.Context, ap *store.Approval) {
		// Stand in for the executor: takes a moment, then records the outcome.
		time.Sleep(300 * time.Millisecond)
		ap.Status = store.StatusExecuted
		ap.ExecutionID = "exe_test"
		if err := m.st.UpdateApproval(ctx, ap); err != nil {
			t.Errorf("persist outcome: %v", err)
		}
	})

	ap, _ := submit(t, m, "DEL orders:1001")
	if _, err := m.Vote(ctx, ap.ID, "ops@example.com", true, "lgtm", ap.ActionHash); err != nil {
		t.Fatalf("vote: %v", err)
	}

	// The vote itself leaves the record at "approved" -- that much is by
	// design, and it is the state a naive waiter stops at.
	stored, err := m.Get(ctx, ap.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Status != store.StatusApproved {
		t.Fatalf("status right after the vote = %s, want approved", stored.Status)
	}
	if m.Settled(store.StatusApproved) {
		t.Fatal("approved was treated as settled: a waiter would report a decision as an outcome")
	}

	final, err := m.Wait(ctx, ap.ID, 5*time.Second)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if final.Status != store.StatusExecuted {
		t.Fatalf("wait returned %s, want executed -- it stopped at the decision, not the outcome", final.Status)
	}
}

// With no resumer there is nothing after the decision, so "approved" is where
// the record stops and waiting for more would only burn the timeout.
func TestWaitReturnsAtTheDecisionWhenNothingExecutes(t *testing.T) {
	ctx := context.Background()
	m := testManager(t, nil)

	ap, _ := submit(t, m, "DEL orders:1001")
	if _, err := m.Vote(ctx, ap.ID, "ops@example.com", true, "lgtm", ap.ActionHash); err != nil {
		t.Fatalf("vote: %v", err)
	}
	final, err := m.Wait(ctx, ap.ID, 2*time.Second)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if final.Status != store.StatusApproved {
		t.Fatalf("wait returned %s, want approved", final.Status)
	}
}

func TestSettledClassification(t *testing.T) {
	withResumer := testManager(t, func(context.Context, *store.Approval) {})
	without := testManager(t, nil)

	cases := []struct {
		status string
		want   bool
	}{
		{store.StatusPending, false},
		{store.StatusApproved, false},
		{store.StatusRejected, true},
		{store.StatusExpired, true},
		{store.StatusExecuted, true},
		{store.StatusFailed, true},
	}
	for _, tc := range cases {
		if got := withResumer.Settled(tc.status); got != tc.want {
			t.Errorf("Settled(%s) with a resumer = %v, want %v", tc.status, got, tc.want)
		}
	}
	if !without.Settled(store.StatusApproved) {
		t.Error("with no resumer, approved is the final state and must count as settled")
	}
}

// An approver states which action they are signing off on. Anything else is a
// different action and must not borrow the vote.
func TestVoteIsBoundToTheActionHash(t *testing.T) {
	ctx := context.Background()
	m := testManager(t, nil)
	ap, _ := submit(t, m, "DEL orders:1001")

	other, err := action.RedisNormalizer{}.Normalize(
		map[string]any{"command": "DEL ORDERS:1001"},
		action.Target{Kind: action.KindRedis, Name: "redis-1", Env: "staging"},
	)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if other.Hash == ap.ActionHash {
		t.Fatal("two different keys produced one hash: the vote would cover both")
	}

	if _, err := m.Vote(ctx, ap.ID, "ops@example.com", true, "lgtm", other.Hash); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a vote quoting a different action hash returned %v, want ErrHashMismatch", err)
	}
	// An empty hash is not "approve anything".
	if _, err := m.Vote(ctx, ap.ID, "ops@example.com", true, "lgtm", ""); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a vote quoting no hash returned %v, want ErrHashMismatch", err)
	}
}

// The end-to-end form of the same rule: an approval was granted for DEL
// orders:1001, and the record is edited to DEL ORDERS:1001 before execution
// reads it. The executor re-verifies the hash and refuses.
func TestLoadActionRefusesAReSpeltRecord(t *testing.T) {
	m := testManager(t, nil)
	ap, approved := submit(t, m, "DEL orders:1001")

	// Sanity: the record as stored is the action that was approved.
	if _, err := LoadAction(ap); err != nil {
		t.Fatalf("the untampered record failed to load: %v", err)
	}

	swapped, err := action.RedisNormalizer{}.Normalize(
		map[string]any{"command": "DEL ORDERS:1001"},
		action.Target{Kind: action.KindRedis, Name: "redis-1", Env: "staging"},
	)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	raw, err := json.Marshal(swapped)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ap.ActionJSON = string(raw)

	_, err = LoadAction(ap)
	if !errors.Is(err, ErrActionTampered) {
		t.Fatalf("Loading a re-spelt record returned %v, want ErrActionTampered", err)
	}
	if approved.Hash == swapped.Hash {
		t.Fatal("the record did not actually change, so the test proves nothing")
	}
}

// A rejected action never reaches the executor, whatever else happens to it.
func TestRejectionIsTerminal(t *testing.T) {
	ctx := context.Background()
	resumed := make(chan struct{}, 1)
	m := testManager(t, func(context.Context, *store.Approval) { resumed <- struct{}{} })

	ap, _ := submit(t, m, "FLUSHALL")
	if _, err := m.Vote(ctx, ap.ID, "ops@example.com", false, "no", ap.ActionHash); err != nil {
		t.Fatalf("vote: %v", err)
	}
	select {
	case <-resumed:
		t.Fatal("a rejected approval invoked the executor")
	case <-time.After(300 * time.Millisecond):
	}
	final, err := m.Wait(ctx, ap.ID, time.Second)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if final.Status != store.StatusRejected {
		t.Fatalf("status = %s, want rejected", final.Status)
	}
}
