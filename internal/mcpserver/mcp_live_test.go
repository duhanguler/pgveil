package mcpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/mcpserver"
	"github.com/duhanguler/pgveil/internal/policy"
)

func callMCPTool(t *testing.T, srv *mcpserver.Server, name string, args map[string]any) (string, bool) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	resp := srv.HandleRequest(context.Background(), mcpserver.RPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  raw,
	})
	if resp == nil || resp.Error != nil {
		t.Fatalf("tool %s RPC error: %+v", name, resp)
	}
	resMap := resp.Result.(map[string]any)
	isErr, _ := resMap["isError"].(bool)
	content := resMap["content"].([]map[string]any)
	return content[0]["text"].(string), isErr
}

func TestMCPServerLiveToolsStdioAndVirtualRLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoPG := demo.NewServer()
	addr, err := demoPG.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("demo start: %v", err)
	}
	mgr, err := policy.LoadBytes(demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", addr))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	dsn := policy.BuildDSN(addr, "pgveil", "", "pgveil_demo", "pgveil-mcp", false)

	// 1. ai_agent MCP server
	srv := mcpserver.NewServer(mgr, "ai_agent", dsn, "0.4.0")

	// list_tables hides api_secrets
	txt, isErr := callMCPTool(t, srv, "list_tables", map[string]any{})
	if isErr || strings.Contains(txt, "api_secrets") || !strings.Contains(txt, "customers") {
		t.Fatalf("unexpected list_tables: err=%v text=%s", isErr, txt)
	}

	// describe_table allowed & denied (bare, schema-qualified, pg_catalog, empty)
	txt, isErr = callMCPTool(t, srv, "describe_table", map[string]any{"table": "customers"})
	if isErr || !strings.Contains(txt, `"masking_strategy"`) {
		t.Fatalf("describe_table(customers) failed: err=%v text=%s", isErr, txt)
	}
	for _, badTbl := range []string{"", ".", "api_secrets", "public.api_secrets", "pg_catalog.pg_shadow"} {
		if _, isErr := callMCPTool(t, srv, "describe_table", map[string]any{"table": badTbl}); !isErr {
			t.Fatalf("expected describe_table(%q) to be denied", badTbl)
		}
	}

	// query: masked SELECT with alias provenance, truncation, blocked AST, HITL required, empty SQL
	txt, isErr = callMCPTool(t, srv, "query", map[string]any{"sql": "SELECT id, full_name AS display_name, email, tckn FROM customers ORDER BY id LIMIT 3"})
	if isErr || strings.Contains(txt, "Ayse Kaya") || strings.Contains(txt, "10000000146") {
		t.Fatalf("expected masked alias output: err=%v text=%s", isErr, txt)
	}
	txt, isErr = callMCPTool(t, srv, "query", map[string]any{"sql": "SELECT id, email FROM customers"})
	if isErr || !strings.Contains(txt, `"truncated": true`) || !strings.Contains(txt, `"row_count": 25`) {
		t.Fatalf("expected row cap truncation at 25: err=%v text=%s", isErr, txt)
	}
	if _, isErr := callMCPTool(t, srv, "query", map[string]any{"sql": ""}); !isErr {
		t.Fatal("expected error for empty SQL")
	}
	if _, isErr := callMCPTool(t, srv, "query", map[string]any{"sql": "DROP TABLE orders"}); !isErr {
		t.Fatal("expected DROP TABLE blocked")
	}
	if _, isErr := callMCPTool(t, srv, "query", map[string]any{"sql": "UPDATE orders SET status='x' WHERE id=1001"}); !isErr {
		t.Fatal("expected HITL write rejected in MCP stdio")
	}

	// explain_query: plain, EXPLAIN prefix, blocked ANALYZE, empty
	txt, isErr = callMCPTool(t, srv, "explain_query", map[string]any{"sql": "SELECT id FROM customers LIMIT 2"})
	if isErr || !strings.Contains(txt, "QUERY PLAN") {
		t.Fatalf("explain_query failed: err=%v text=%s", isErr, txt)
	}
	if _, isErr := callMCPTool(t, srv, "explain_query", map[string]any{"sql": "EXPLAIN SELECT id FROM customers"}); isErr {
		t.Fatal("expected EXPLAIN SELECT allowed")
	}
	if _, isErr := callMCPTool(t, srv, "explain_query", map[string]any{"sql": "EXPLAIN ANALYZE SELECT 1"}); !isErr {
		t.Fatal("expected EXPLAIN ANALYZE blocked")
	}
	if _, isErr := callMCPTool(t, srv, "explain_query", map[string]any{"sql": ""}); !isErr {
		t.Fatal("expected empty explain_query error")
	}
	if _, isErr := callMCPTool(t, srv, "unknown_tool", map[string]any{}); !isErr {
		t.Fatal("expected unknown tool error")
	}

	// 2. Virtual RLS through MCP (`tenant_tr`)
	rlsSrv := mcpserver.NewServer(mgr, "tenant_tr", "", "0.4.0") // exercises dialDB fallback from policyMgr!
	txt, isErr = callMCPTool(t, rlsSrv, "query", map[string]any{"sql": "SELECT id, city, tckn FROM customers ORDER BY id"})
	if isErr || !strings.Contains(txt, `"rls_rewritten": true`) || !strings.Contains(txt, `"row_count": 9`) || strings.Contains(txt, "Ankara") {
		t.Fatalf("expected Virtual RLS filtering in MCP: err=%v text=%s", isErr, txt)
	}

	// 3. ServeStdio JSON-RPC 2.0 stream (initialize, notification, ping, tools/list, invalid JSON, bad params, unknown method)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":"bad"}`,
		`{"jsonrpc":"2.0","id":5,"method":"nonexistent/method"}`,
		`{not-valid-json`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := srv.ServeStdio(ctx, strings.NewReader(in), &out); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}
	gotOut := out.String()
	if !strings.Contains(gotOut, "pgveil-mcp") || !strings.Contains(gotOut, "-32700") || !strings.Contains(gotOut, "-32601") || !strings.Contains(gotOut, "-32602") {
		t.Fatalf("unexpected ServeStdio output: %s", gotOut)
	}
}
