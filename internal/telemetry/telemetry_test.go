package telemetry

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewMetricsAndInitTracer(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	if m == nil || m.QueriesTotal == nil || m.ActiveConnections == nil {
		t.Fatal("expected initialized Metrics instruments")
	}
	m.QueriesTotal.WithLabelValues("ai_agent", "SELECT", "MASKED").Inc()
	m.BlockedTotal.WithLabelValues("ai_agent", "block_ddl", "CRITICAL").Inc()
	m.PIIFieldsMasked.WithLabelValues("ai_agent", "tckn").Add(3)
	m.RowsReturned.WithLabelValues("ai_agent").Add(10)
	m.RowsTruncated.WithLabelValues("ai_agent").Add(5)
	m.HITLDecisions.WithLabelValues("ai_agent", "approved").Inc()
	m.ActiveConnections.Inc()
	m.ActiveConnections.Dec()
	m.ProxyOverheadUs.WithLabelValues("ai_agent").Observe(120)
	m.UpstreamDurationUs.WithLabelValues("ai_agent").Observe(450)
	m.KafkaPublished.WithLabelValues("pgveil.audit.queries", "ok").Inc()

	families, err := reg.Gather()
	if err != nil || len(families) < 8 {
		t.Fatalf("expected gathered metrics, err=%v count=%d", err, len(families))
	}

	ctx := context.Background()
	tr, shutdown := InitTracer(ctx, "pgveil-test", false, "")
	if tr == nil || shutdown == nil {
		t.Fatal("expected local tracer and shutdown func")
	}
	_, span := tr.Start(ctx, "test.op")
	span.End()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown local tracer: %v", err)
	}

	tr2, shutdown2 := InitTracer(ctx, "pgveil-test-otlp", true, "127.0.0.1:4317")
	if tr2 == nil || shutdown2 == nil {
		t.Fatal("expected otlp tracer and shutdown func")
	}
	_ = shutdown2(ctx)
}
