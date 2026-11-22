package firewall

import (
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/policy"
)

func TestFirewallASTWalkAndTautologyCoverage(t *testing.T) {
	prof := &policy.RoleProfile{
		Name: "strict",
		Firewall: policy.FirewallPolicy{
			AllowStatements:         []string{"SELECT", "EXPLAIN", "SHOW"},
			BlockDDL:                true,
			BlockMultiStatement:     true,
			BlockWriteWithoutWhere:  true,
			BlockDangerousFunctions: true,
			BlockSystemCatalogs:     true,
			BlockPIIInference:       true,
			ProtectedColumns:        []string{"tckn", "iban", "ssn"},
			RequireHITLStatements:   []string{"UPDATE", "DELETE", "INSERT", "MERGE"},
			DeniedTables:            []string{"api_secrets"},
			BlockSelectStarOnPII:    true,
		},
	}

	// Cover every DDL statement category in ast_walk.go
	ddlQueries := []string{
		"CREATE TABLE evil (id int)",
		"CREATE TABLE evil AS SELECT * FROM customers",
		"CREATE INDEX idx_c ON customers(id)",
		"CREATE VIEW v_c AS SELECT id FROM customers",
		"CREATE FUNCTION f() RETURNS int AS 'SELECT 1' LANGUAGE SQL",
		"GRANT SELECT ON customers TO public",
		"GRANT pg_read_all_data TO evil",
		"ALTER SYSTEM SET log_statement = 'all'",
		"ALTER TABLE customers ADD COLUMN x text",
		"ALTER TABLE customers RENAME TO customers2",
		"ALTER TABLE customers OWNER TO evil",
		"TRUNCATE customers",
		"DROP TABLE public.customers",
		"DROP OWNED BY evil",
		"CREATE SUBSCRIPTION sub CONNECTION 'host=x' PUBLICATION p",
		"CREATE FOREIGN DATA WRAPPER fdw",
		"CREATE ROLE hacker",
		"VACUUM customers",
		"SELECT id INTO new_tbl FROM customers",
		"LOAD '/tmp/evil.so'",
		"COMMENT ON TABLE customers IS 'x'",
	}
	for _, q := range ddlQueries {
		dec := Evaluate(q, prof)
		if dec.Action != ActionBlock {
			t.Fatalf("expected DDL %q blocked, got %+v", q, dec)
		}
	}

	// Cover non-DDL top-level statements & housekeeping
	for _, q := range []string{
		"BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT s1", "RELEASE SAVEPOINT s1",
		"DEALLOCATE ALL", "DISCARD ALL", "CLOSE cur1", "UNLISTEN ch",
		"SET client_encoding = 'UTF8'",
		"SHOW server_version",
		"SELECT 1",
		"   ",
		";",
	} {
		dec := Evaluate(q, prof)
		if dec.Action != ActionAllow {
			t.Fatalf("expected housekeeping %q allowed, got %+v", q, dec)
		}
	}

	// Cover non-allowed statements (LISTEN, NOTIFY, FETCH, EXECUTE, CALL, DECLARE CURSOR)
	for _, q := range []string{
		"LISTEN ch", "NOTIFY ch, 'msg'", "FETCH NEXT FROM cur", "EXECUTE p1",
		"CALL safe_proc(1)", "CALL pg_sleep(1)",
		"DECLARE cur CURSOR FOR SELECT id FROM customers",
		"PREPARE p1 AS SELECT id FROM customers",
		"COPY customers TO PROGRAM 'id'",
		"COPY (SELECT id FROM customers) TO STDOUT",
		"DO $$ BEGIN PERFORM 1; END $$",
		"SET ROLE postgres",
		"RESET ALL",
		"SELECT * FROM customers", // block_select_star
		"SELECT id FROM pg_catalog.pg_authid",
		"SELECT id FROM pg_toast.pg_toast_12345",
		"SELECT id FROM customers; SELECT 2",
	} {
		dec := Evaluate(q, prof)
		if dec.Action != ActionBlock {
			t.Fatalf("expected %q blocked, got %+v", q, dec)
		}
	}

	// Cover expression AST walk + PII taint nodes (Window, MinMax, Array, Row, Indirection, JSON, XML, Subquery)
	taintQueries := []string{
		"SELECT id, ROW_NUMBER() OVER (PARTITION BY tckn ORDER BY id) FROM customers",
		"SELECT id, GREATEST(tckn, '0') FROM customers",
		"SELECT id, ARRAY[tckn] FROM customers",
		"SELECT id, ROW(tckn, id) FROM customers",
		"SELECT id, (ARRAY[tckn])[1] FROM customers",
		"SELECT id, XMLSERIALIZE(CONTENT XMLELEMENT(NAME x, tckn) AS text) FROM customers",
		"SELECT id, JSON_OBJECTAGG('k': tckn) FROM customers",
		"SELECT id, JSON_ARRAYAGG(tckn) FROM customers",
		"SELECT id, JSON_VALUE(tckn::jsonb, '$.a') FROM customers",
		"SELECT * FROM JSON_TABLE(tckn::jsonb, '$' COLUMNS (a text PATH '$')) jt",
		"SELECT * FROM XMLTABLE('/x' PASSING tckn::xml COLUMNS a text PATH '.') xt",
		"SELECT id FROM customers WHERE CASE WHEN tckn = '1' THEN true ELSE false END",
		"SELECT id FROM customers WHERE COALESCE(tckn, 'x') = 'x'",
		"SELECT id FROM customers WHERE tckn IS NOT NULL",
		"SELECT id FROM customers WHERE (tckn = '1') IS TRUE",
		"SELECT id, tckn FROM customers GROUP BY 1, 2",
		"SELECT id FROM customers LIMIT (SELECT CASE WHEN tckn = '1' THEN 1 ELSE 2 END FROM customers LIMIT 1)",
	}
	for _, q := range taintQueries {
		dec := Evaluate(q, prof)
		if dec.Action != ActionBlock {
			t.Fatalf("expected taint query %q blocked, got %+v", q, dec)
		}
	}

	// Cover tautology & contradiction arithmetic/boolean branches
	tautQueries := []string{
		"DELETE FROM orders WHERE 2 * 3 = 6",
		"DELETE FROM orders WHERE 10 / 2 = 5",
		"DELETE FROM orders WHERE 7 % 4 = 3",
		"DELETE FROM orders WHERE 5 - 2 = 3",
		"DELETE FROM orders WHERE +1 = 1",
		"DELETE FROM orders WHERE -1 = -1",
		"DELETE FROM orders WHERE 1::int = 1",
		"DELETE FROM orders WHERE 1 != 2",
		"DELETE FROM orders WHERE 1 < 2",
		"DELETE FROM orders WHERE 2 <= 2",
		"DELETE FROM orders WHERE 3 >= 2",
		"DELETE FROM orders WHERE 'a' = 'a'",
		"DELETE FROM orders WHERE 'a' <> 'b'",
		"DELETE FROM orders WHERE 'b' > 'a'",
		"DELETE FROM orders WHERE 'b' >= 'a'",
		"DELETE FROM orders WHERE 'a' < 'b'",
		"DELETE FROM orders WHERE 'a' <= 'a'",
		"DELETE FROM orders WHERE true = true",
		"DELETE FROM orders WHERE true <> false",
		"DELETE FROM orders WHERE NOT ('a' = 'b')",
		"DELETE FROM orders WHERE NOT (true = false)",
		"DELETE FROM orders WHERE NOT (id <> id)",
		"DELETE FROM orders WHERE NOT (1 = 2)",
		"DELETE FROM orders WHERE NOT (false)",
		"DELETE FROM orders WHERE NOT (0::int)",
		"DELETE FROM orders WHERE NOT (1 = 1 AND 1 = 2)",
		"DELETE FROM orders WHERE NOT (1 = 2 OR 2 = 3)",
		"DELETE FROM orders WHERE NOT (NOT (1 = 1))",
		"DELETE FROM orders WHERE (1 = 2) IS FALSE",
		"DELETE FROM orders WHERE (1 = 2) IS NOT TRUE",
		"DELETE FROM orders WHERE NULL IS NULL",
		"DELETE FROM orders WHERE 1 IN (1, 2)",
		"DELETE FROM orders WHERE 5 BETWEEN 1 AND 10",
		"DELETE FROM orders WHERE 5 BETWEEN SYMMETRIC 10 AND 1",
		"DELETE FROM orders WHERE 'abc' LIKE '%'",
		"DELETE FROM orders WHERE 'abc' ILIKE 'abc'",
		"DELETE FROM orders WHERE id IS NOT DISTINCT FROM id",
		"DELETE FROM orders WHERE COALESCE(NULL, true)",
		"DELETE FROM orders WHERE CASE WHEN 1=1 THEN true ELSE false END",
		"DELETE FROM orders WHERE EXISTS (SELECT 1)",
		"UPDATE orders SET status = 'x' FROM customers WHERE 1 = 1 RETURNING id",
		"DELETE FROM orders USING customers WHERE 1 = 1 RETURNING id",
		"MERGE INTO orders o USING customers c ON 1 = 1 WHEN MATCHED THEN UPDATE SET status = 'x'",
	}
	for _, q := range tautQueries {
		dec := Evaluate(q, prof)
		if dec.Action != ActionBlock || dec.Rule != "block_write_without_where" {
			t.Fatalf("expected tautology block for %q, got %+v", q, dec)
		}
	}

	// Scoped writes trigger HITL
	for _, q := range []string{
		"INSERT INTO orders (customer_id, order_number, status, total_amount) SELECT id, 'X', 'new', 10 FROM customers WHERE id = 1 RETURNING id",
		"UPDATE orders SET status = 'ok' WHERE id = 1001 RETURNING id",
		"DELETE FROM orders WHERE id = 1001 RETURNING id",
		"MERGE INTO orders o USING customers c ON o.customer_id = c.id WHEN MATCHED AND o.id = 1001 THEN UPDATE SET status = 'ok'",
	} {
		dec := Evaluate(q, prof)
		if dec.Action != ActionRequireHITL {
			t.Fatalf("expected REQUIRE_HITL for %q, got %+v", q, dec)
		}
	}

	// Nil profile, oversized SQL, NUL byte, admin wildcard parse fallback
	if dec := Evaluate("SELECT 1", nil); dec.Action != ActionAllow {
		t.Fatal("nil profile should allow")
	}
	if dec := Evaluate("SELECT 'a\x00b'", prof); dec.Rule != "invalid_nul_byte" {
		t.Fatalf("expected invalid_nul_byte, got %+v", dec)
	}
	if dec := Evaluate("SELECT '"+strings.Repeat("a", MaxSQLBytes+10)+"'", prof); dec.Rule != "sql_size_limit" {
		t.Fatalf("expected sql_size_limit, got %+v", dec)
	}
	adminProf := &policy.RoleProfile{Name: "admin", Firewall: policy.FirewallPolicy{AllowStatements: []string{"*"}}}
	if dec := Evaluate("NOT VALID SQL %%%", adminProf); dec.Action != ActionAllow {
		t.Fatalf("admin wildcard should pass raw SQL, got %+v", dec)
	}
}

func TestRewriteWithRLS_ExtendedStatementsAndJoins(t *testing.T) {
	prof := &policy.RoleProfile{
		Name: "rls_full",
		Firewall: policy.FirewallPolicy{
			RowFilters: []policy.RowFilterPolicy{
				{
					Table:     "customers",
					Predicate: "COALESCE(city, 'Istanbul') = 'Istanbul' AND tier IS NOT NULL AND (active IS TRUE) AND id::text != '' AND CASE WHEN tier = 'vip' THEN true ELSE true END AND lower(city) IN ('istanbul') AND city = ANY(ARRAY['Istanbul'])",
				},
				{Table: "orders", Predicate: "currency = 'TRY'"},
			},
		},
	}

	queries := []string{
		"SELECT c.id, o.id FROM customers c RIGHT JOIN orders o ON c.id = o.customer_id",
		"SELECT id FROM customers LEFT JOIN orders USING (id)",
		"SELECT id FROM customers RIGHT JOIN orders USING (id)",
		"SELECT id FROM public.customers",
		"WITH RECURSIVE r AS (SELECT id FROM customers WHERE id = 1 UNION ALL SELECT c.id FROM customers c JOIN r ON c.id = r.id) SELECT * FROM r",
		"INSERT INTO archive SELECT id FROM customers RETURNING (SELECT count(*) FROM orders)",
		"UPDATE orders o SET status = COALESCE((SELECT tier FROM customers WHERE id = o.customer_id), 'ok') FROM customers c WHERE o.customer_id = c.id RETURNING o.id",
		"DELETE FROM orders o USING customers c WHERE o.customer_id = c.id RETURNING o.id",
		"EXPLAIN SELECT id FROM customers",
		"PREPARE p1 AS SELECT id FROM customers",
		"DECLARE cur CURSOR FOR SELECT id FROM customers",
		"COPY (SELECT id FROM customers) TO STDOUT",
		"MERGE INTO orders o USING customers c ON o.customer_id = c.id WHEN MATCHED THEN UPDATE SET status = 'ok'",
		"SELECT id FROM customers UNION SELECT customer_id FROM orders",
		"SELECT id FROM (SELECT id FROM customers) sub",
		"SELECT id, (SELECT count(*) FROM orders WHERE orders.customer_id = c.id), CASE WHEN EXISTS (SELECT 1 FROM orders) THEN 1 ELSE 0 END, ROW((SELECT id FROM orders LIMIT 1), 1) FROM customers c GROUP BY id HAVING count(*) > (SELECT 0 FROM orders LIMIT 1) ORDER BY (SELECT 1 FROM orders LIMIT 1) LIMIT (SELECT 5 FROM orders LIMIT 1) OFFSET (SELECT 0 FROM orders LIMIT 1)",
	}
	for _, q := range queries {
		res, err := RewriteWithRLS(q, prof, SessionContext{DBUser: "alice", Database: "prod"})
		if err != nil {
			t.Fatalf("RewriteWithRLS failed for %q: %v", q, err)
		}
		if !res.Rewritten {
			t.Fatalf("expected rewrite for %q", q)
		}
		assertValidPGSQL(t, res.SQL)
	}
}
