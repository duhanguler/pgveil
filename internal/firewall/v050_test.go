package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/policy"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func TestTypedJWTClaimsRLSInjectionAndFailClosed(t *testing.T) {
	prof := &policy.RoleProfile{
		Name: "tenant_jwt",
		Firewall: policy.FirewallPolicy{
			RowFilters: []policy.RowFilterPolicy{
				{Table: "customers", Predicate: "city = {{jwt.city}} AND email LIKE '%@{{jwt.domain}}'"},
			},
		},
	}

	// 1. Fail-closed when required {{jwt.*}} claim is missing or blank
	if _, err := RewriteWithRLS("SELECT id FROM customers", prof, SessionContext{DBUser: "app"}); !errors.Is(err, ErrMissingRLSClaim) {
		t.Fatalf("expected ErrMissingRLSClaim when Claims nil, got %v", err)
	}
	if _, err := RewriteWithRLS("SELECT id FROM customers", prof, SessionContext{
		Claims: map[string]string{"city": "Istanbul", "domain": "   "},
	}); !errors.Is(err, ErrMissingRLSClaim) {
		t.Fatalf("expected ErrMissingRLSClaim when claim blank, got %v", err)
	}

	// 2. Adversarial SQLi torture payloads inside JWT claims MUST produce pure A_Const string literals
	adversarialCities := []string{
		"Istanbul' OR '1'='1",
		"$$dollar$$; DROP TABLE customers; --",
		`E'\'; DELETE FROM orders; /*`,
		"Ankara\x00Hidden",
		"O'Reilly''s",
	}
	for _, payload := range adversarialCities {
		res, err := RewriteWithRLS("SELECT id, full_name FROM customers", prof, SessionContext{
			Claims: map[string]string{
				"city":   payload,
				"domain": "corp.tr' OR 1=1 --",
			},
		})
		if err != nil || !res.Rewritten {
			t.Fatalf("RewriteWithRLS failed for payload %q: res=%+v err=%v", payload, res, err)
		}
		tree, perr := pg_query.Parse(res.SQL)
		if perr != nil {
			t.Fatalf("deparsed SQL invalid for payload %q: %s (%v)", payload, res.SQL, perr)
		}
		if len(tree.Stmts) != 1 {
			t.Fatalf("SQLi broke statement boundary! stmts=%d sql=%s", len(tree.Stmts), res.SQL)
		}
		sel := tree.Stmts[0].Stmt.GetSelectStmt()
		if sel == nil || sel.WhereClause == nil {
			t.Fatalf("expected single SELECT with WHERE, got %s", res.SQL)
		}
		// Ensure NO OR_EXPR was smuggled into the WHERE clause!
		if containsOrExpr(sel.WhereClause) {
			t.Fatalf("SQLi injected OR_EXPR into AST for payload %q: %s", payload, res.SQL)
		}
	}
}

func containsOrExpr(n *pg_query.Node) bool {
	if n == nil {
		return false
	}
	if be := n.GetBoolExpr(); be != nil {
		if be.Boolop == pg_query.BoolExprType_OR_EXPR {
			return true
		}
		for _, a := range be.Args {
			if containsOrExpr(a) {
				return true
			}
		}
	}
	if ae := n.GetAExpr(); ae != nil {
		return containsOrExpr(ae.Lexpr) || containsOrExpr(ae.Rexpr)
	}
	return false
}

func TestTimeoutBypassASTGuardAndInspectExplain(t *testing.T) {
	prof := &policy.RoleProfile{
		Name: "timed_agent",
		Firewall: policy.FirewallPolicy{
			AllowStatements:  []string{"SELECT", "SET", "DISCARD"},
			MaxQueryDuration: "5s",
		},
	}

	bypassAttempts := []string{
		"SET statement_timeout = 0",
		"SET LOCAL statement_timeout = '999s'",
		"SET lock_timeout = 0",
		"RESET statement_timeout",
		"RESET ALL",
		"DISCARD ALL",
		"SELECT set_config('STATEMENT_TIMEOUT', '0', false)",
		"SELECT set_config(lower('STATEMENT_TIMEOUT'), '0', false)",
	}
	for _, q := range bypassAttempts {
		dec := Evaluate(q, prof)
		if dec.Action != ActionBlock || dec.Rule != "block_timeout_bypass" {
			t.Fatalf("expected block_timeout_bypass for %q, got %+v", q, dec)
		}
	}

	// Safe non-timeout session statements remain allowed
	for _, safe := range []string{"DISCARD PLANS", "DISCARD TEMP", "SET application_name = 'ok'"} {
		dec := Evaluate(safe, prof)
		if dec.Action != ActionAllow {
			t.Fatalf("expected %q allowed, got %+v", safe, dec)
		}
	}

	// InspectExplainPlanOnly AST checks
	for _, bad := range []string{
		"",
		"ANALYZE SELECT * FROM customers",
		"EXPLAIN ANALYZE SELECT * FROM customers",
		"EXPLAIN (/*sneaky*/ ANALYZE) DELETE FROM orders WHERE id = 1",
		"EXPLAIN (ANALYZE true, FORMAT JSON) SELECT 1",
		"SELECT 1; SELECT 2",
	} {
		if _, err := InspectExplainPlanOnly(bad); err == nil {
			t.Fatalf("expected InspectExplainPlanOnly to reject %q", bad)
		}
	}
	for _, good := range []string{
		"SELECT id FROM customers WHERE id = 1",
		"EXPLAIN SELECT id FROM customers WHERE id = 1",
		"EXPLAIN (ANALYZE false, FORMAT JSON) SELECT 1",
	} {
		out, err := InspectExplainPlanOnly(good)
		if err != nil || !strings.HasPrefix(strings.ToUpper(out), "EXPLAIN") {
			t.Fatalf("expected InspectExplainPlanOnly(%q) to succeed, got out=%q err=%v", good, out, err)
		}
	}
}

func TestSidebandCostRunnerPlanCacheAndThresholds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoSrv := demo.NewServer()
	addr, err := demoSrv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := policy.LoadBytes(demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", addr))
	if err != nil {
		t.Fatal(err)
	}
	prof, ok := mgr.GetProfileByName("ai_agent")
	if !ok {
		t.Fatal("missing ai_agent profile")
	}

	runner := NewCostRunner(mgr, "")
	defer runner.Close()

	// 1. Bounded query passes (miss on 1st call, cache hit on 2nd call)
	qSafe := "SELECT id, email FROM customers WHERE id = 1"
	fpSafe, _ := pg_query.Fingerprint(qSafe)
	v1 := runner.Check(ctx, qSafe, fpSafe, nil, prof)
	if !v1.Evaluated || v1.CacheHit || v1.Blocked || v1.Metrics == nil {
		t.Fatalf("unexpected 1st cost verdict: %+v", v1)
	}
	v2 := runner.Check(ctx, qSafe, fpSafe, nil, prof)
	if !v2.Evaluated || !v2.CacheHit || v2.Blocked {
		t.Fatalf("expected 2nd cost verdict to hit PlanCache, got %+v", v2)
	}

	// 2. 3-way unindexed Cartesian join exceeds max_total_cost (92400 > 50000) -> BLOCKED!
	qBomb := "SELECT c.id FROM customers c, orders o, payments p"
	fpBomb, _ := pg_query.Fingerprint(qBomb)
	vBomb := runner.Check(ctx, qBomb, fpBomb, nil, prof)
	if !vBomb.Blocked || vBomb.Rule != "cost_guard_max_cost" {
		t.Fatalf("expected cost_guard_max_cost block on cartesian join, got %+v", vBomb)
	}

	// 3. SeqScan table block + max_estimated_rows check
	seqProf := *prof
	seqProf.Firewall.CostGuard = policy.CostGuardPolicy{
		Enabled:            true,
		BlockSeqScanTables: []string{"customers"},
	}
	vSeq := runner.Check(ctx, "SELECT id FROM customers", "fp_seq_cust", nil, &seqProf)
	if !vSeq.Blocked || vSeq.Rule != "cost_guard_seq_scan" {
		t.Fatalf("expected cost_guard_seq_scan block, got %+v", vSeq)
	}

	rowProf := *prof
	rowProf.Firewall.CostGuard = policy.CostGuardPolicy{
		Enabled:          true,
		MaxEstimatedRows: 10,
	}
	vRows := runner.Check(ctx, "SELECT id FROM customers", "fp_rows_cust", nil, &rowProf)
	if !vRows.Blocked || vRows.Rule != "cost_guard_max_rows" {
		t.Fatalf("expected cost_guard_max_rows block, got %+v", vRows)
	}

	// 4. Unreachable upstream: fail-open by default vs fail-closed when configured
	badRunner := NewCostRunner(mgr, "postgres://pgveil@127.0.0.1:1/pgveil_demo?sslmode=disable")
	defer badRunner.Close()
	fo := badRunner.Check(ctx, "SELECT id FROM customers WHERE id = $1", "fp_param", nil, prof)
	if !fo.Fallback || fo.Blocked {
		t.Fatalf("expected fail-open fallback, got %+v", fo)
	}
	fcProf := *prof
	fcProf.Firewall.CostGuard.FailClosed = true
	fc := badRunner.Check(ctx, "SELECT id FROM customers WHERE id = $1", "fp_param2", nil, &fcProf)
	if !fc.Fallback || !fc.Blocked || fc.Rule != "cost_guard_explain_failed" {
		t.Fatalf("expected fail-closed block, got %+v", fc)
	}

	// 5. PlanCache LRU eviction & TTL expiration
	tinyCache := NewPlanCache(2, 15*time.Millisecond)
	tinyCache.Put("k1", PlanMetrics{TotalCost: 1})
	tinyCache.Put("k2", PlanMetrics{TotalCost: 2})
	tinyCache.Put("k3", PlanMetrics{TotalCost: 3})
	if _, ok := tinyCache.Get("k1"); ok {
		t.Fatal("expected k1 evicted by maxEntries=2")
	}
	time.Sleep(25 * time.Millisecond)
	if _, ok := tinyCache.Get("k3"); ok {
		t.Fatal("expected k3 expired by TTL")
	}

	// 6. ClassifyForCostGuard & complex sentinel AST expression coverage
	paramQueries := []string{
		"WITH c AS (SELECT id FROM customers WHERE id = $1) SELECT COALESCE($2, CASE WHEN c.id = $3 THEN $4::text ELSE 'x' END) FROM c JOIN orders o ON c.id = o.customer_id WHERE EXISTS (SELECT 1 FROM payments p WHERE p.order_id = $5) UNION SELECT 'a'",
		"UPDATE orders SET status = $1 FROM customers c WHERE orders.customer_id = c.id AND c.id = $2",
		"DELETE FROM orders USING customers c WHERE orders.customer_id = c.id AND c.id = $1",
		"MERGE INTO orders o USING customers c ON o.customer_id = c.id AND c.id = $1 WHEN MATCHED THEN UPDATE SET status = 'ok'",
	}
	for _, pq := range paramQueries {
		exp, hp := ClassifyForCostGuard(pq)
		if !exp || !hp {
			t.Fatalf("expected ClassifyForCostGuard(%q) -> (true, true), got (%v, %v)", pq, exp, hp)
		}
	}
	if exp, _ := ClassifyForCostGuard("SHOW server_version"); exp {
		t.Fatal("SHOW should not be classified as explainable")
	}

	richPredProf := &policy.RoleProfile{
		Name: "rich_rls",
		Firewall: policy.FirewallPolicy{
			RowFilters: []policy.RowFilterPolicy{
				{
					Table:     "customers",
					Predicate: "COALESCE({{jwt.city}}, 'x')::text = ANY(ARRAY[{{jwt.city}}]) AND GREATEST({{jwt.city}}, 'a') IS NOT NULL AND (CASE city WHEN {{jwt.city}} THEN true ELSE false END) IS TRUE AND ROW(city, {{jwt.city}}) = ROW('a', 'b') AND lower({{db_user}}) != {{database}} AND {{application_name}} != {{profile}}",
				},
			},
		},
	}
	richRes, err := RewriteWithRLS("SELECT id FROM customers", richPredProf, SessionContext{
		DBUser:          "u",
		Database:        "d",
		ApplicationName: "app",
		RoleProfile:     "rich_rls",
		Claims:          map[string]string{"city": "Istanbul's"},
	})
	if err != nil || !richRes.Rewritten {
		t.Fatalf("rich sentinel AST rewrite failed: res=%+v err=%v", richRes, err)
	}
}

func TestSecurityBugHuntRegressions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoSrv := demo.NewServer()
	addr, err := demoSrv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := policy.LoadBytes(demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", addr))
	if err != nil {
		t.Fatal(err)
	}
	prof, ok := mgr.GetProfileByName("ai_agent")
	if !ok {
		t.Fatal("missing ai_agent profile")
	}
	runner := NewCostRunner(mgr, "")
	defer runner.Close()

	// Bug #2 Regression: PlanCache MUST NOT be poisoned by constant-blind pg_query.Fingerprint!
	// Both LIMIT 5 and LIMIT 99999999 produce the exact same pg_query.Fingerprint, yet LIMIT 5
	// is cheap while LIMIT 99999999 triggers a 92,400-cost Cartesian join.
	qSmall := "SELECT c.id FROM customers c, orders o, payments p LIMIT 5"
	qHuge := "SELECT c.id FROM customers c, orders o, payments p LIMIT 99999999"
	fpSmall, _ := pg_query.Fingerprint(qSmall)
	fpHuge, _ := pg_query.Fingerprint(qHuge)
	if fpSmall != fpHuge {
		t.Fatalf("precondition failed: expected identical fingerprints, got %s vs %s", fpSmall, fpHuge)
	}
	vSmall := runner.Check(ctx, qSmall, fpSmall, nil, prof)
	if !vSmall.Evaluated || vSmall.Blocked {
		t.Fatalf("expected LIMIT 5 query to pass Cost Guard, got %+v", vSmall)
	}
	vHuge := runner.Check(ctx, qHuge, fpHuge, nil, prof)
	if !vHuge.Blocked || vHuge.CacheHit || vHuge.Rule != "cost_guard_max_cost" {
		t.Fatalf("PlanCache poisoning regression! Expected LIMIT 99999999 to miss cache and block, got %+v", vHuge)
	}
	// CanonicalSQLKey collapses unquoted whitespace while preserving quoted spaces verbatim
	if CanonicalSQLKey("SELECT   1  WHERE  x = 'a  b'") != "SELECT 1 WHERE x = 'a  b'" {
		t.Fatalf("unexpected CanonicalSQLKey: %q", CanonicalSQLKey("SELECT   1  WHERE  x = 'a  b'"))
	}

	// Bug #11 Regression: Multi-statement Simple Query cannot bypass Cost Guard with trailing "; SELECT 1"
	multiBomb := "SELECT c.id FROM customers c, orders o, payments p; SELECT 1;"
	vMulti := runner.Check(ctx, multiBomb, "", nil, prof)
	if !vMulti.Blocked || vMulti.Rule != "cost_guard_max_cost" {
		t.Fatalf("multi-statement Cost Guard bypass regression! Got %+v", vMulti)
	}

	// Bug #12 Regression: CROSS JOIN in embedded demo execExplain properly deparses with PG Version
	crossBomb := "SELECT c.id FROM customers c CROSS JOIN orders o"
	vCross := runner.Check(ctx, crossBomb, "", nil, prof)
	if !vCross.Blocked || vCross.Rule != "cost_guard_max_cost" {
		t.Fatalf("CROSS JOIN demo EXPLAIN deparse regression! Got %+v", vCross)
	}

	// Bug #5a Regression: Cross-claim sentinel substitution MUST NOT happen when claim A contains token B
	twoClaimProf := &policy.RoleProfile{
		Name: "two_claim",
		Firewall: policy.FirewallPolicy{
			RowFilters: []policy.RowFilterPolicy{
				{
					Table:     "customers",
					Predicate: "city = {{jwt.a}} AND country = {{jwt.b}}",
				},
			},
		},
	}
	resCross, err := RewriteWithRLS("SELECT id FROM customers", twoClaimProf, SessionContext{
		Claims: map[string]string{
			"a": "__pgveil_ph_1__",
			"b": "SECRET_TENANT",
		},
	})
	if err != nil || !resCross.Rewritten {
		t.Fatalf("two-claim RLS rewrite failed: %v", err)
	}
	if !strings.Contains(resCross.SQL, "'__pgveil_ph_1__'") || strings.Count(resCross.SQL, "SECRET_TENANT") != 1 {
		t.Fatalf("cross-claim sentinel injection detected in rewritten SQL: %s", resCross.SQL)
	}

	// Bug #5b Regression: qualifyColumns must qualify columns inside MinMaxExpr (GREATEST) and RowExpr (ROW)
	joinQualProf := &policy.RoleProfile{
		Name: "join_qual",
		Firewall: policy.FirewallPolicy{
			RowFilters: []policy.RowFilterPolicy{
				{
					Table:     "customers",
					Predicate: "GREATEST(city, 'A') <> '' AND ROW(city, id) IS NOT NULL",
				},
			},
		},
	}
	resJoin, err := RewriteWithRLS("SELECT c.id FROM customers c JOIN orders o ON c.id = o.customer_id", joinQualProf, SessionContext{})
	if err != nil || !resJoin.Rewritten {
		t.Fatalf("join MinMax/Row qualification failed: %v", err)
	}
	if !strings.Contains(resJoin.SQL, "GREATEST(c.city, 'A')") || !strings.Contains(resJoin.SQL, "ROW(c.city, c.id)") {
		t.Fatalf("expected c.city and c.id qualified inside GREATEST/ROW, got: %s", resJoin.SQL)
	}
}
