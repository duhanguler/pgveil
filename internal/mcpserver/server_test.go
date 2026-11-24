package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/policy"
)

func TestMCPHandshakeToolsAndASTBlocking(t *testing.T) {
	mgr, err := policy.LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(mgr, "ai_agent", "", "0.2.0-test")

	// Feed initialize, tools/list, and 4 blocked tool calls over stdio
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT id FROM customers WHERE tckn LIKE '100%'"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"describe_table","arguments":{"table":"api_secrets"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"describe_table","arguments":{"table":"public.api_secrets"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"explain_query","arguments":{"sql":"(ANALYZE) SELECT * FROM customers"}}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := srv.ServeStdio(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("ServeStdio failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 JSON-RPC responses (notification produces none), got %d:\n%s", len(lines), out.String())
	}

	// Verify initialize
	var r1 map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &r1)
	res1 := r1["result"].(map[string]any)
	if res1["protocolVersion"] != ProtocolVersion {
		t.Fatalf("unexpected protocolVersion: %v", res1["protocolVersion"])
	}

	// Verify side-channel PII query blocked cleanly before hitting any DB
	if !strings.Contains(lines[2], "pii_side_channel_inference") {
		t.Fatalf("expected side-channel PII block in response 3, got: %s", lines[2])
	}

	// Verify describe_table refuses BOTH bare "api_secrets" AND schema-qualified "public.api_secrets"
	if !strings.Contains(lines[3], "restricted table") {
		t.Fatalf("expected restricted table denial in response 4, got: %s", lines[3])
	}
	if !strings.Contains(lines[4], "restricted table") {
		t.Fatalf("expected schema-qualified restricted table denial in response 5, got: %s", lines[4])
	}

	// Verify explain_query rejects ANALYZE execution
	if !strings.Contains(lines[5], "disallows EXPLAIN ANALYZE") {
		t.Fatalf("expected EXPLAIN ANALYZE block in response 6, got: %s", lines[5])
	}
}

func TestMCPProtocolNegotiationAnnotationsAndInspectPolicy(t *testing.T) {
	mgr, err := policy.LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(mgr, "tenant_tr", "", "0.5.1-test")

	// 1. Negotiate newer MCP protocol revision & verify server instructions
	initResp := srv.HandleRequest(context.Background(), RPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2025-11-25"}`),
	})
	initRes := initResp.Result.(map[string]any)
	if initRes["protocolVersion"] != "2025-11-25" {
		t.Fatalf("expected negotiated protocolVersion 2025-11-25, got %v", initRes["protocolVersion"])
	}
	if instr, _ := initRes["instructions"].(string); !strings.Contains(instr, "list_tables") {
		t.Fatalf("expected actionable MCP instructions, got: %q", instr)
	}

	// 2. Verify all 5 tools publish title, strict schema, and read-only annotations
	listResp := srv.HandleRequest(context.Background(), RPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list"})
	tools := listResp.Result.(map[string]any)["tools"].([]map[string]any)
	if len(tools) != 5 {
		t.Fatalf("expected 5 MCP tools, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool["title"] == "" || tool["description"] == "" {
			t.Fatalf("tool %v missing title or description", tool["name"])
		}
		ann, ok := tool["annotations"].(map[string]any)
		if !ok || ann["readOnlyHint"] != true || ann["destructiveHint"] != false {
			t.Fatalf("tool %v missing expected read-only annotations: %v", tool["name"], tool["annotations"])
		}
		schema := tool["inputSchema"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatalf("tool %v schema missing additionalProperties:false", tool["name"])
		}
	}

	// 3. Verify prompts/list, resources/list, and ping succeed cleanly
	for _, method := range []string{"prompts/list", "resources/list", "ping"} {
		resp := srv.HandleRequest(context.Background(), RPCRequest{JSONRPC: "2.0", ID: 3, Method: method})
		if resp.Error != nil {
			t.Fatalf("method %s returned unexpected error: %v", method, resp.Error)
		}
	}

	// 4. Verify inspect_policy works offline with Virtual RLS rewrite preview
	rlsResp := srv.HandleRequest(context.Background(), RPCRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"inspect_policy","arguments":{"sql":"SELECT id, full_name FROM customers"}}`),
	})
	rlsText := rlsResp.Result.(map[string]any)["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(rlsText, `"rls_rewritten": true`) || !strings.Contains(rlsText, "Istanbul") {
		t.Fatalf("expected Virtual RLS rewrite preview in inspect_policy, got:\n%s", rlsText)
	}

	// 5. Verify inspect_policy reports BLOCK on destructive SQL without DB connection
	blockResp := srv.HandleRequest(context.Background(), RPCRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"inspect_policy","arguments":{"sql":"DROP TABLE orders"}}`),
	})
	blockText := blockResp.Result.(map[string]any)["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(blockText, `"action": "BLOCK"`) {
		t.Fatalf("expected BLOCK decision in inspect_policy, got:\n%s", blockText)
	}

	// 6. Verify error paths for unknown method and invalid tool params
	if errResp := srv.HandleRequest(context.Background(), RPCRequest{JSONRPC: "2.0", ID: 6, Method: "no/such/method"}); errResp.Error == nil || errResp.Error.Code != -32601 {
		t.Fatalf("expected -32601 error for unknown method, got: %+v", errResp)
	}
	if badParams := srv.HandleRequest(context.Background(), RPCRequest{JSONRPC: "2.0", ID: 7, Method: "tools/call", Params: json.RawMessage(`{invalid`)}); badParams.Error == nil || badParams.Error.Code != -32602 {
		t.Fatalf("expected -32602 error for invalid tool params, got: %+v", badParams)
	}
}
