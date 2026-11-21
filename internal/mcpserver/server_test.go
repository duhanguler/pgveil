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
