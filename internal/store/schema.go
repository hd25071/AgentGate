package store

import (
	"strings"

	"github.com/hd25071/AgentGate/internal/id"
)

// schema returns the DDL for a dialect. Statement order matters only in that
// tables must exist before their indexes.
func schema(dialect string) []string {
	serial := "INTEGER PRIMARY KEY AUTOINCREMENT"
	if dialect == "postgres" {
		serial = "BIGSERIAL PRIMARY KEY"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS audit_records (
			seq        ` + serial + `,
			id         TEXT   NOT NULL UNIQUE,
			request_id TEXT   NOT NULL,
			ts         BIGINT NOT NULL,
			type       TEXT   NOT NULL,
			payload    TEXT   NOT NULL,
			prev_hash  TEXT   NOT NULL,
			hash       TEXT   NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_records (request_id)`,

		`CREATE TABLE IF NOT EXISTS approvals (
			id                 TEXT PRIMARY KEY,
			request_id         TEXT   NOT NULL,
			subject            TEXT   NOT NULL,
			tool               TEXT   NOT NULL,
			summary            TEXT   NOT NULL,
			action_hash        TEXT   NOT NULL,
			action_json        TEXT   NOT NULL,
			decision_json      TEXT   NOT NULL,
			risk               TEXT   NOT NULL,
			reasons            TEXT   NOT NULL,
			flags              TEXT   NOT NULL,
			required_approvals INTEGER NOT NULL,
			approvals_json     TEXT   NOT NULL,
			status             TEXT   NOT NULL,
			created_at         BIGINT NOT NULL,
			updated_at         BIGINT NOT NULL,
			expires_at         BIGINT NOT NULL,
			preview_json       TEXT   NOT NULL DEFAULT '',
			result_json        TEXT   NOT NULL DEFAULT '',
			execution_id       TEXT   NOT NULL DEFAULT '',
			decision_note      TEXT   NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals (status, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_approvals_hash ON approvals (action_hash)`,

		`CREATE TABLE IF NOT EXISTS executions (
			id            TEXT PRIMARY KEY,
			request_id    TEXT   NOT NULL,
			approval_id   TEXT   NOT NULL DEFAULT '',
			action_hash   TEXT   NOT NULL,
			adapter       TEXT   NOT NULL,
			status        TEXT   NOT NULL,
			result_json   TEXT   NOT NULL DEFAULT '',
			snapshot_json TEXT   NOT NULL DEFAULT '',
			rollback_json TEXT   NOT NULL DEFAULT '',
			error         TEXT   NOT NULL DEFAULT '',
			started_at    BIGINT NOT NULL,
			finished_at   BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_exec_request ON executions (request_id)`,
	}
}

func newAuditID() string { return id.New("aud") }

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
