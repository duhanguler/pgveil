package telemetry

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Metrics holds all Prometheus instruments exposed by pgveil.
type Metrics struct {
	QueriesTotal       *prometheus.CounterVec
	BlockedTotal       *prometheus.CounterVec
	PIIFieldsMasked    *prometheus.CounterVec
	RowsReturned       *prometheus.CounterVec
	RowsTruncated      *prometheus.CounterVec
	HITLDecisions      *prometheus.CounterVec
	ActiveConnections  prometheus.Gauge
	ProxyOverheadUs    *prometheus.HistogramVec
	UpstreamDurationUs *prometheus.HistogramVec
	KafkaPublished     *prometheus.CounterVec
}

// NewMetrics registers pgveil Prometheus metrics on the provided registerer.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	f := promauto.With(reg)
	return &Metrics{
		QueriesTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pgveil_queries_total",
			Help: "Total PostgreSQL queries inspected by pgveil.",
		}, []string{"role", "statement_type", "decision"}),
		BlockedTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pgveil_blocked_queries_total",
			Help: "Total queries blocked by the AST SQL firewall.",
		}, []string{"role", "rule", "risk_level"}),
		PIIFieldsMasked: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pgveil_pii_fields_masked_total",
			Help: "Total PII/secret cells dynamically masked on the wire.",
		}, []string{"role", "entity_type"}),
		RowsReturned: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pgveil_rows_returned_total",
			Help: "Total DataRow frames forwarded to clients.",
		}, []string{"role"}),
		RowsTruncated: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pgveil_rows_truncated_total",
			Help: "Total DataRow frames truncated by row-exfiltration budgets.",
		}, []string{"role"}),
		HITLDecisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pgveil_hitl_decisions_total",
			Help: "Total Human-in-the-Loop query approval outcomes.",
		}, []string{"role", "status"}),
		ActiveConnections: f.NewGauge(prometheus.GaugeOpts{
			Name: "pgveil_active_connections",
			Help: "Current active PostgreSQL wire connections through pgveil.",
		}),
		ProxyOverheadUs: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "pgveil_proxy_overhead_microseconds",
			Help:    "pgveil AST firewall and wire masking overhead in microseconds.",
			Buckets: []float64{25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000},
		}, []string{"role"}),
		UpstreamDurationUs: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "pgveil_upstream_duration_microseconds",
			Help:    "Upstream PostgreSQL query execution time in microseconds.",
			Buckets: []float64{100, 250, 500, 1000, 2500, 5000, 10000, 50000, 100000, 500000},
		}, []string{"role"}),
		KafkaPublished: f.NewCounterVec(prometheus.CounterOpts{
			Name: "pgveil_kafka_events_total",
			Help: "Total audit and security alert events published to Kafka.",
		}, []string{"topic", "status"}),
	}
}

// InitTracer configures OpenTelemetry tracing (OTLP gRPC when enabled, local SDK tracer otherwise).
func InitTracer(ctx context.Context, serviceName string, enabled bool, endpoint string) (trace.Tracer, func(context.Context) error) {
	res, _ := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)

	var opts []sdktrace.TracerProviderOption
	opts = append(opts, sdktrace.WithResource(res))

	if enabled && endpoint != "" {
		dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		exp, err := otlptracegrpc.New(dialCtx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			slog.Warn("otel exporter unavailable, continuing with local trace IDs", "endpoint", endpoint, "err", err)
		} else {
			opts = append(opts, sdktrace.WithBatcher(exp))
			slog.Info("opentelemetry tracing enabled", "endpoint", endpoint)
		}
	}

	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	return tp.Tracer(serviceName), tp.Shutdown
}
