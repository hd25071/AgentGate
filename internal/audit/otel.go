package audit

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// TracingConfig configures the OTLP exporter.
type TracingConfig struct {
	// Endpoint is an OTLP/HTTP endpoint such as "otel-collector:4318".
	// Empty disables export and leaves the global tracer as a no-op.
	Endpoint string
	Insecure bool
	// SampleRate in [0,1]. 1 records everything.
	SampleRate     float64
	ServiceName    string
	ServiceVersion string
}

// SetupTracing installs a global tracer provider.
//
// The returned shutdown function flushes buffered spans; the gateway calls it
// on SIGTERM so the last traces of a shutdown are not lost.
func SetupTracing(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if cfg.Endpoint == "" {
		return noop, nil
	}
	if cfg.SampleRate <= 0 {
		cfg.SampleRate = 1
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "agentgate"
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return noop, fmt.Errorf("build OTLP exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.ServiceVersion),
	))
	if err != nil {
		res = resource.Default()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}
