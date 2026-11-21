package firewall

import (
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/policy"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func tenantProfile() *policy.RoleProfile {
	return &policy.RoleProfile{
		Name: "tenant_tr",
		Firewall: policy.FirewallPolicy{
			AllowStatements:        []string{"SELECT", "EXPLAIN", "SHOW"},
			BlockDDL:               true,
			BlockMultiStatement:    true,
			BlockWriteWithoutWhere: true,
			RowFilters: []policy.RowFilterPolicy{
				{Table: "customers", Predicate: "city = 'Istanbul'"},
				{Table: "orders", Predicate: "currency = 'TRY'"},
			},
		},
	}
}

func assertValidPGSQL(t *testing.T, sql string) {
	t.Helper()
	if _, err := pg_query.Parse(sql); err != nil {
		t.Fatalf("rewritten SQL failed PG17 parse: %v\nSQL: %s", err, sql)
	}
}

func TestRewriteWithRLS_ZeroOverheadFastPath(t *testing.T) {
	noRLS := &policy.RoleProfile{Name: "plain"}
	res, err := RewriteWithRLS("SELECT * FROM customers", noRLS, SessionContext{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if res.Rewritten || res.SQL != "SELECT * FROM customers" {
		t.Fatalf("expected untouched SQL on fast path, got %+v", res)
	}
}

func TestRewriteWithRLS_SimpleSelectAndOrPrecedence(t *testing.T) {
	prof := tenantProfile()

	// 1. Plain SELECT without WHERE
	res, err := RewriteWithRLS("SELECT id, full_name FROM customers LIMIT 10", prof, SessionContext{})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	if !res.Rewritten {
		t.Fatal("expected rewrite=true")
	}
	assertValidPGSQL(t, res.SQL)
	if !strings.Contains(res.SQL, "customers.city = 'Istanbul'") {
		t.Fatalf("expected qualified city predicate, got: %s", res.SQL)
	}

	// 2. Existing WHERE with OR — must wrap OR inside parentheses!
	res2, err := RewriteWithRLS("SELECT id FROM customers WHERE tier = 'vip' OR tier = 'gold'", prof, SessionContext{})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, res2.SQL)
	if !strings.Contains(res2.SQL, "(tier = 'vip' OR tier = 'gold') AND customers.city = 'Istanbul'") {
		t.Fatalf("expected parenthesized OR precedence, got: %s", res2.SQL)
	}
}

func TestRewriteWithRLS_JoinsAndAliases(t *testing.T) {
	prof := tenantProfile()

	// 1. INNER JOIN with aliases: columns qualified by alias c and o
	res, err := RewriteWithRLS(
		"SELECT c.id, o.order_number FROM customers c INNER JOIN orders o ON c.id = o.customer_id",
		prof, SessionContext{},
	)
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, res.SQL)
	if !strings.Contains(res.SQL, "c.city = 'Istanbul'") || !strings.Contains(res.SQL, "o.currency = 'TRY'") {
		t.Fatalf("expected alias-qualified predicates for both tables, got: %s", res.SQL)
	}
	if len(res.RulesApplied) != 2 {
		t.Fatalf("expected 2 rules applied, got %v", res.RulesApplied)
	}

	// 2. LEFT JOIN: left table predicate in WHERE, right table predicate in ON clause!
	resLeft, err := RewriteWithRLS(
		"SELECT c.id, o.order_number FROM customers c LEFT JOIN orders o ON c.id = o.customer_id",
		prof, SessionContext{},
	)
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resLeft.SQL)
	whereIdx := strings.Index(strings.ToUpper(resLeft.SQL), " WHERE ")
	onIdx := strings.Index(strings.ToUpper(resLeft.SQL), " ON ")
	orderPredIdx := strings.Index(resLeft.SQL, "o.currency = 'TRY'")
	custPredIdx := strings.Index(resLeft.SQL, "c.city = 'Istanbul'")
	if onIdx < 0 || whereIdx < 0 || orderPredIdx < onIdx || orderPredIdx > whereIdx {
		t.Fatalf("LEFT JOIN right-side predicate must be placed in ON clause before WHERE; got: %s", resLeft.SQL)
	}
	if custPredIdx < whereIdx {
		t.Fatalf("LEFT JOIN left-side predicate should be in WHERE clause; got: %s", resLeft.SQL)
	}

	// 3. FULL OUTER JOIN: wraps filtered tables in subqueries so no unauthorized rows leak
	resFull, err := RewriteWithRLS(
		"SELECT c.id, o.id FROM customers c FULL OUTER JOIN orders o ON c.id = o.customer_id",
		prof, SessionContext{},
	)
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resFull.SQL)
	if !strings.Contains(resFull.SQL, "(SELECT * FROM customers WHERE customers.city = 'Istanbul') c") ||
		!strings.Contains(resFull.SQL, "(SELECT * FROM orders WHERE orders.currency = 'TRY') o") {
		t.Fatalf("FULL OUTER JOIN must wrap filtered tables as subqueries; got: %s", resFull.SQL)
	}
}

func TestRewriteWithRLS_CTEShadowingAndUnionAndSubqueries(t *testing.T) {
	prof := tenantProfile()

	// 1. CTE shadowing base table name `customers` — must filter INSIDE CTE and NOT re-inject on outer CTE read!
	resCTE, err := RewriteWithRLS(
		"WITH customers AS (SELECT id, full_name FROM customers) SELECT id, full_name FROM customers",
		prof, SessionContext{},
	)
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resCTE.SQL)
	if count := strings.Count(resCTE.SQL, "city = 'Istanbul'"); count != 1 {
		t.Fatalf("expected exactly 1 filter injection inside CTE (none on outer shadowed CTE), got count=%d SQL=%s", count, resCTE.SQL)
	}

	// 2. UNION branches
	resUnion, err := RewriteWithRLS(
		"SELECT id FROM customers WHERE tier = 'vip' UNION ALL SELECT customer_id FROM orders",
		prof, SessionContext{},
	)
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resUnion.SQL)
	if !strings.Contains(resUnion.SQL, "customers.city = 'Istanbul'") || !strings.Contains(resUnion.SQL, "orders.currency = 'TRY'") {
		t.Fatalf("expected both UNION branches rewritten, got: %s", resUnion.SQL)
	}

	// 3. Subquery in WHERE IN (...)
	resSub, err := RewriteWithRLS(
		"SELECT id, amount FROM payments WHERE order_id IN (SELECT id FROM orders)",
		prof, SessionContext{},
	)
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resSub.SQL)
	if !strings.Contains(resSub.SQL, "orders.currency = 'TRY'") {
		t.Fatalf("expected subquery rewritten, got: %s", resSub.SQL)
	}
}

func TestRewriteWithRLS_DMLAndExtendedParams(t *testing.T) {
	prof := tenantProfile()

	// 1. Scoped UPDATE with $1 parameter preserved intact
	resUpd, err := RewriteWithRLS("UPDATE orders SET status = $1 WHERE id = $2", prof, SessionContext{})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resUpd.SQL)
	if !strings.Contains(resUpd.SQL, "$1") || !strings.Contains(resUpd.SQL, "$2") || !strings.Contains(resUpd.SQL, "orders.currency = 'TRY'") {
		t.Fatalf("expected $1/$2 preserved and orders filter injected, got: %s", resUpd.SQL)
	}

	// 2. Scoped DELETE
	resDel, err := RewriteWithRLS("DELETE FROM orders o WHERE o.id = 1001", prof, SessionContext{})
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resDel.SQL)
	if !strings.Contains(resDel.SQL, "o.currency = 'TRY'") {
		t.Fatalf("expected DELETE alias filter, got: %s", resDel.SQL)
	}

	// 3. MERGE statement
	resMerge, err := RewriteWithRLS(
		"MERGE INTO orders o USING customers c ON o.customer_id = c.id WHEN MATCHED THEN UPDATE SET status = 'done'",
		prof, SessionContext{},
	)
	if err != nil {
		t.Fatalf("rewrite error: %v", err)
	}
	assertValidPGSQL(t, resMerge.SQL)
	if !strings.Contains(resMerge.SQL, "o.currency = 'TRY'") || !strings.Contains(resMerge.SQL, "c.city = 'Istanbul'") {
		t.Fatalf("expected MERGE ON condition to include both target & source predicates, got: %s", resMerge.SQL)
	}

	// 4. Security Ordering Invariant: unscoped DELETE MUST be blocked by Evaluate BEFORE RLS runs!
	dec := Evaluate("DELETE FROM orders", prof)
	if dec.Action != ActionBlock || dec.Rule != "block_write_without_where" {
		t.Fatalf("unscoped DELETE must be blocked before RLS injection, got %+v", dec)
	}
}

func TestRewriteWithRLS_SessionPlaceholdersSQLiSafe(t *testing.T) {
	prof := &policy.RoleProfile{
		Name: "session_scoped",
		Firewall: policy.FirewallPolicy{
			RowFilters: []policy.RowFilterPolicy{
				{Table: "customers", Predicate: "city = '{{application_name}}' AND owner = {{db_user}}"},
			},
		},
	}
	// Crafted SQL-injection attempt inside application_name & db_user
	sess := SessionContext{
		DBUser:          "alice' OR 1=1 --",
		ApplicationName: "evil' OR '1'='1",
		Database:        "prod",
	}
	res, err := RewriteWithRLS("SELECT id FROM customers", prof, sess)
	if err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}
	assertValidPGSQL(t, res.SQL)
	// Verify parsed WHERE AST contains ONLY safe string constants, never injected OR expressions!
	tree, err := pg_query.Parse(res.SQL)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	where := tree.Stmts[0].Stmt.GetSelectStmt().WhereClause
	if isTautology(where) {
		t.Fatalf("crafted session value produced a tautology! SQL: %s", res.SQL)
	}
	if !strings.Contains(res.SQL, "evil'' OR ''1''=''1") {
		t.Fatalf("expected single quotes doubled safely inside string literal, got: %s", res.SQL)
	}
}

func TestPolicyRowFilterValidation(t *testing.T) {
	validYAML := `
default_profile: tenant
profiles:
  - name: tenant
    firewall:
      allow_statements: ["SELECT"]
      row_filters:
        - table: customers
          predicate: "city = 'Istanbul' AND owner = '{{db_user}}'"
`
	if _, err := policy.LoadBytes([]byte(validYAML)); err != nil {
		t.Fatalf("expected valid row_filters YAML to load, got: %v", err)
	}

	badCases := []struct {
		name string
		pred string
	}{
		{"empty_predicate", ""},
		{"syntax_error", "city = AND 'Istanbul'"},
		{"multi_stmt", "city = 'Istanbul'; DROP TABLE customers"},
		{"subquery_rejected", "id IN (SELECT id FROM api_secrets)"},
		{"dangerous_func", "pg_read_file('/etc/passwd') = 'x'"},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			yml := "default_profile: t\nprofiles:\n  - name: t\n    firewall:\n      row_filters:\n        - table: customers\n          predicate: \"" + tc.pred + "\"\n"
			if _, err := policy.LoadBytes([]byte(yml)); err == nil {
				t.Fatalf("expected invalid row_filter %q to fail validation", tc.name)
			}
		})
	}
}
