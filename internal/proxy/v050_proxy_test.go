package proxy_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/proxy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
)

func TestWireProxyStartupTimeoutCostGuardAndTxSafety(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoPG := demo.NewServer()
	upAddr, err := demoPG.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := policy.LoadBytes(demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", upAddr))
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	metrics := telemetry.NewMetrics(reg)
	tracer, shutdown := telemetry.InitTracer(ctx, "pgveil-cost-test", false, "")
	defer func() { _ = shutdown(context.Background()) }()
	bus := events.NewBus(100, policy.KafkaConfig{}, metrics)
	defer bus.Close()
	hitlMgr := hitl.NewManager(50)

	srv, err := proxy.NewServer(mgr, hitlMgr, bus, metrics, tracer)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Start(ctx) }()
	for i := 0; i < 50 && srv.Addr() == ""; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	// Connect using Extended Query Protocol (default pgx mode) as ai_agent (max_query_duration: 5s + cost_guard enabled)
	dsn := policy.BuildDSN(srv.Addr(), "pgveil", "", "pgveil_demo", "ai_agent", false)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer conn.Close(ctx)

	// 1. Inside an explicit BEGIN ... COMMIT transaction, parameterized Extended Protocol queries work seamlessly
	// with sideband Cost Guard (proving unnamed portals & txStatus == 'T' are never corrupted!)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("BEGIN failed: %v", err)
	}
	var email string
	if err := tx.QueryRow(ctx, "SELECT email FROM customers WHERE id = $1", 1).Scan(&email); err != nil {
		t.Fatalf("tx parameterized SELECT failed: %v", err)
	}
	if !strings.Contains(email, "***") {
		t.Fatalf("expected masked email inside tx, got %q", email)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("COMMIT failed: %v", err)
	}

	// 2. Timeout bypass attempts (SET statement_timeout = 0 / DISCARD ALL) are blocked with SQLSTATE 42501
	for _, bypassSQL := range []string{"SET statement_timeout = 0", "DISCARD ALL"} {
		_, err := conn.Exec(ctx, bypassSQL)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("expected 42501 block on %q, got %v", bypassSQL, err)
		}
	}

	// 3. Unindexed 3-way Cartesian join is blocked by Cost Guard with SQLSTATE 54000 BEFORE execution!
	_, err = conn.Exec(ctx, "SELECT c.id FROM customers c, orders o, payments p")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "54000" || !strings.Contains(pgErr.Message, "max_total_cost") {
		t.Fatalf("expected SQLSTATE 54000 Cost Guard block, got %v", err)
	}

	// Verify connection remains healthy on next query AND AuditEvent recorded EstimatedCost > 50000
	var cnt int
	if err := conn.QueryRow(ctx, "SELECT id FROM customers WHERE id = $1", 2).Scan(&cnt); err != nil || cnt != 2 {
		t.Fatalf("connection unhealthy after Cost Guard block: cnt=%d err=%v", cnt, err)
	}

	evs := bus.Recent(10, "BLOCKED", "ai_agent")
	foundCostAudit := false
	for _, ev := range evs {
		if ev.PolicyRule == "cost_guard_max_cost" && ev.EstimatedCost > 50000 {
			foundCostAudit = true
			break
		}
	}
	if !foundCostAudit {
		t.Fatalf("expected BLOCKED AuditEvent with EstimatedCost > 50000, got %+v", evs)
	}
}
