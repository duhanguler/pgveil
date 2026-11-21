package demo_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/discover"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/proxy"
	"github.com/jackc/pgx/v5"
)

func TestDemoServer_DirectPgxAndDiscover(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := demo.NewServer()
	addr, err := srv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("demo server start: %v", err)
	}

	dsn := policy.BuildDSN(addr, "pgveil", "", "pgveil_demo", "demo-test", false)

	// 1. Default pgx/v5 Extended Query (binary int4 + text!)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("pgx connect: %v", err)
	}
	defer conn.Close(context.Background())

	var dbName string
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&dbName); err != nil {
		t.Fatalf("current_database: %v", err)
	}
	if dbName != "pgveil_demo" {
		t.Fatalf("expected pgveil_demo, got %q", dbName)
	}

	// Parameterized query ($1)
	var id int
	var name, city string
	if err := conn.QueryRow(ctx, "SELECT id, full_name, city FROM customers WHERE id = $1", 1).Scan(&id, &name, &city); err != nil {
		t.Fatalf("parameterized SELECT: %v", err)
	}
	if id != 1 || name != "Ayse Kaya" || city != "Istanbul" {
		t.Fatalf("unexpected row: id=%d name=%q city=%q", id, name, city)
	}

	// JOIN query
	rows, err := conn.Query(ctx, "SELECT c.id, o.order_number, o.currency FROM customers c INNER JOIN orders o ON c.id = o.customer_id ORDER BY o.id")
	if err != nil {
		t.Fatalf("JOIN query: %v", err)
	}
	joinCount := 0
	for rows.Next() {
		var cid int
		var onum, curr string
		if err := rows.Scan(&cid, &onum, &curr); err != nil {
			t.Fatalf("scan join row: %v", err)
		}
		joinCount++
	}
	rows.Close()
	if joinCount != 8 {
		t.Fatalf("expected 8 joined orders, got %d", joinCount)
	}

	// 2. Live PII Discovery (discover.Scan) directly against embedded demo server!
	report, err := discover.Scan(ctx, dsn, 50, "test-secret")
	if err != nil {
		t.Fatalf("discover.Scan against demo server failed: %v", err)
	}
	if report.TablesScanned != 5 {
		t.Fatalf("expected 5 tables scanned, got %d", report.TablesScanned)
	}
	if report.FindingsCount < 10 {
		t.Fatalf("expected >=10 PII findings, got %d", report.FindingsCount)
	}
	if len(report.RecommendedTables) == 0 || report.RecommendedTables[0] != "api_secrets" {
		t.Fatalf("expected api_secrets in recommended denied_tables, got %v", report.RecommendedTables)
	}
}

func TestDemoServer_FullProxyWithMaskingHITLAndVirtualRLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start zero-dependency embedded demo upstream
	demoSrv := demo.NewServer()
	upstreamAddr, err := demoSrv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("demo server start: %v", err)
	}

	cfgYAML := `
server:
  listen_addr: "127.0.0.1:0"
  upstream_addr: "` + upstreamAddr + `"
  upstream_user: "pgveil"
  upstream_database: "pgveil_demo"
security:
  masking_secret: "demo-test-hmac-secret"
  compliance_packs: ["gdpr", "kvkk", "pci-dss", "hipaa", "secrets"]
default_profile: "ai_agent"
profiles:
  - name: "ai_agent"
    match:
      application_names: ["ai_agent"]
    firewall:
      allow_statements: ["SELECT", "EXPLAIN", "SHOW"]
      block_ddl: true
      block_multi_statement: true
      block_write_without_where: true
      block_dangerous_functions: true
      block_pii_inference: true
      protected_columns: ["tckn", "iban"]
      require_hitl_statements: ["UPDATE"]
      hitl_mode: "hold"
      hitl_timeout: "5s"
      denied_tables: ["api_secrets"]
      max_rows: 25
      max_rows_action: "truncate"
    masking:
      enabled: true
      auto_detect_pii: true
      column_rules:
        - column: "tckn"
          strategy: "partial"
        - column: "email"
          strategy: "partial"
  - name: "tenant_tr"
    match:
      application_names: ["tenant_tr"]
    firewall:
      allow_statements: ["SELECT", "EXPLAIN", "SHOW"]
      block_ddl: true
      block_multi_statement: true
      block_write_without_where: true
      row_filters:
        - table: "customers"
          predicate: "city = 'Istanbul'"
        - table: "orders"
          predicate: "currency = 'TRY'"
    masking:
      enabled: true
      auto_detect_pii: true
      column_rules:
        - column: "tckn"
          strategy: "partial"
        - column: "email"
          strategy: "partial"
`
	policyMgr, err := policy.LoadBytes([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	hitlMgr := hitl.NewManager(50)
	eventBus := events.NewBus(100, policy.KafkaConfig{}, nil)
	defer eventBus.Close()

	wireProxy, err := proxy.NewServer(policyMgr, hitlMgr, eventBus, nil, nil)
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	go func() { _ = wireProxy.Start(ctx) }()

	// Wait for proxy listener
	var proxyAddr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := wireProxy.Addr(); a != "" {
			proxyAddr = a
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if proxyAddr == "" {
		t.Fatal("proxy did not bind in time")
	}

	// --- Test 1: ai_agent masking + row cap + AST block ---
	aiDSN := policy.BuildDSN(proxyAddr, "pgveil", "", "pgveil_demo", "ai_agent", false)
	aiConn, err := pgx.Connect(ctx, aiDSN)
	if err != nil {
		t.Fatalf("connect ai_agent: %v", err)
	}
	defer aiConn.Close(context.Background())

	var tckn, email string
	if err := aiConn.QueryRow(ctx, "SELECT tckn, email FROM customers WHERE id = 1").Scan(&tckn, &email); err != nil {
		t.Fatalf("ai_agent SELECT: %v", err)
	}
	if tckn == "10000000146" || !strings.Contains(tckn, "*") {
		t.Fatalf("expected masked TCKN, got %q", tckn)
	}
	if email == "ayse.kaya@example.com.tr" || !strings.Contains(email, "*") {
		t.Fatalf("expected masked email, got %q", email)
	}

	// Blocked PII oracle probe
	if _, err := aiConn.Exec(ctx, "SELECT id FROM customers WHERE tckn LIKE '100%'"); err == nil {
		t.Fatal("expected PII side-channel probe to be blocked")
	}

	// --- Test 2: Live HITL hold & approve UPDATE ---
	go func() {
		for i := 0; i < 50; i++ {
			pending := hitlMgr.List("PENDING")
			if len(pending) > 0 {
				_, _ = hitlMgr.Resolve(pending[0].ID, true, "tester", "approved in test")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	tag, err := aiConn.Exec(ctx, "UPDATE orders SET status = 'refunded' WHERE id = 1001")
	if err != nil {
		t.Fatalf("HITL-approved UPDATE failed: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expected 1 row updated, got %d", tag.RowsAffected())
	}

	// --- Test 3: Virtual RLS (`tenant_tr`) via Extended Query AND Simple Query ---
	tenantDSN := policy.BuildDSN(proxyAddr, "pgveil", "", "pgveil_demo", "tenant_tr", false)
	tConn, err := pgx.Connect(ctx, tenantDSN)
	if err != nil {
		t.Fatalf("connect tenant_tr: %v", err)
	}
	defer tConn.Close(context.Background())

	// Query ALL customers without any WHERE — Virtual RLS MUST return ONLY Istanbul rows!
	rows, err := tConn.Query(ctx, "SELECT id, city, tckn FROM customers ORDER BY id")
	if err != nil {
		t.Fatalf("tenant_tr SELECT customers: %v", err)
	}
	custCount := 0
	for rows.Next() {
		var cid int
		var city, maskedTCKN string
		if err := rows.Scan(&cid, &city, &maskedTCKN); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if city != "Istanbul" {
			t.Fatalf("Virtual RLS leaked non-Istanbul customer id=%d city=%q", cid, city)
		}
		if maskedTCKN == "10000000146" {
			t.Fatalf("expected PII masking alongside Virtual RLS, got raw TCKN")
		}
		custCount++
	}
	rows.Close()
	if custCount != 9 { // customer #1 + gs in 11..40 where gs%4==0 (12,16,20,24,28,32,36,40 -> 8 + 1 = 9)
		t.Fatalf("expected 9 Istanbul customers, got %d", custCount)
	}

	// Parameterized JOIN with Extended Query ($1) — both customers & orders filtered by Virtual RLS!
	jRows, err := tConn.Query(ctx,
		"SELECT c.city, o.currency, o.status FROM customers c JOIN orders o ON c.id = o.customer_id WHERE o.id >= $1",
		1000,
	)
	if err != nil {
		t.Fatalf("tenant_tr parameterized JOIN: %v", err)
	}
	jCount := 0
	for jRows.Next() {
		var city, curr, st string
		if err := jRows.Scan(&city, &curr, &st); err != nil {
			t.Fatalf("scan join: %v", err)
		}
		if city != "Istanbul" || curr != "TRY" {
			t.Fatalf("Virtual RLS JOIN leak: city=%q currency=%q", city, curr)
		}
		if st != "refunded" {
			t.Fatalf("expected persisted HITL UPDATE status='refunded', got %q", st)
		}
		jCount++
	}
	jRows.Close()
	if jCount != 1 { // Only order 1001 belongs to Istanbul customer #1 AND has currency TRY!
		t.Fatalf("expected 1 Istanbul+TRY order, got %d", jCount)
	}

	// Verify AuditEvent recorded RLS rewrite metadata!
	recent := eventBus.Recent(10, "", "tenant_tr")
	foundRLSEvent := false
	for _, ev := range recent {
		if ev.RLSRewritten && len(ev.RLSRulesApplied) > 0 && strings.Contains(ev.RewrittenSQLPreview, "Istanbul") {
			foundRLSEvent = true
			break
		}
	}
	if !foundRLSEvent {
		t.Fatalf("expected AuditEvent with RLSRewritten=true for tenant_tr, got %+v", recent)
	}
}
