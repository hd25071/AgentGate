// Package audit is the gateway's memory.
//
// Two things travel together here: the hash-chained record in the database,
// which is what an incident review reads, and the OpenTelemetry span, which is
// what a trace UI shows. They share a request id so the two views line up.
package audit

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/hd25071/AgentGate/internal/id"
	"github.com/hd25071/AgentGate/internal/store"
)

// Recorder writes to both the database and the trace stream.
type Recorder struct {
	st     store.Store
	tracer trace.Tracer
	log    *slog.Logger
}

// New builds a Recorder. Tracer comes from the global provider, which is a
// no-op unless SetupTracing configured an exporter.
func New(st store.Store, log *slog.Logger) *Recorder {
	if log == nil {
		log = slog.Default()
	}
	return &Recorder{
		st:     st,
		tracer: otel.Tracer("agentgate"),
		log:    log,
	}
}

// Store exposes the underlying store for read-only queries.
func (r *Recorder) Store() store.Store { return r.st }

// Record appends one event to the chain and returns the sealed record.
//
// A failure to write the audit chain is never swallowed silently: the caller
// gets an error and decides. In the gateway, an audit failure on the
// execute path aborts the action -- an unauditable action is a denied action.
func (r *Recorder) Record(ctx context.Context, requestID, evType string, payload any) (store.AuditRecord, error) {
	rec, err := r.st.AppendAudit(ctx, store.AuditRecord{
		ID:        id.New("aud"),
		RequestID: requestID,
		TS:        time.Now().UnixMilli(),
		Type:      evType,
		Payload:   store.MarshalPayload(payload),
	})
	if err != nil {
		r.log.Error("audit append failed", "event", evType, "request_id", requestID, "err", err)
		return rec, err
	}
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.AddEvent(evType, trace.WithAttributes(
			attribute.String("agentgate.request_id", requestID),
			attribute.Int64("agentgate.audit_seq", rec.Seq),
			attribute.String("agentgate.audit_hash", rec.Hash),
		))
	}
	return rec, nil
}

// MustRecord is Record for events whose loss is a bug rather than an incident.
func (r *Recorder) MustRecord(ctx context.Context, requestID, evType string, payload any) store.AuditRecord {
	rec, err := r.Record(ctx, requestID, evType, payload)
	if err != nil {
		r.log.Error("audit append failed (best effort)", "event", evType, "err", err)
	}
	return rec
}

// Start begins a span for one request.
func (r *Recorder) Start(ctx context.Context, requestID, name string) (context.Context, trace.Span) {
	return r.tracer.Start(ctx, name,
		trace.WithAttributes(
			attribute.String("agentgate.request_id", requestID),
			attribute.String("service.name", "agentgate"),
		))
}

// Fail marks a span as failed without ending it.
func Fail(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// Timeline is the replay view of one request.
type Timeline struct {
	RequestID string              `json:"request_id"`
	Records   []store.AuditRecord `json:"records"`
	Verified  bool                `json:"chain_verified"`
	Broken    string              `json:"chain_problem,omitempty"`
}

// Replay loads the ordered timeline for a request.
func (r *Recorder) Replay(ctx context.Context, requestID string) (Timeline, error) {
	recs, err := r.st.AuditByRequest(ctx, requestID)
	if err != nil {
		return Timeline{}, err
	}
	tl := Timeline{RequestID: requestID, Records: recs, Verified: true}
	// Verify the sub-chain: every record must link to the one before it.
	prev := ""
	for i, rec := range recs {
		if i == 0 {
			prev = rec.Hash
			continue
		}
		if rec.PrevHash != prev {
			tl.Verified = false
			tl.Broken = "record " + rec.ID + " does not link to its predecessor"
			break
		}
		prev = rec.Hash
	}
	return tl, nil
}

// Verify runs a full chain verification.
func (r *Recorder) Verify(ctx context.Context) (store.ChainReport, error) {
	return r.st.VerifyChain(ctx)
}
