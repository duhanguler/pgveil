package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/policy"
)

func TestCLIHelpersAndSubcommands(t *testing.T) {
	if got := formatDisplayHostPort(":6432"); got != "127.0.0.1:6432" {
		t.Fatalf("got %q", got)
	}
	if got := formatDisplayHostPort("0.0.0.0:8088"); got != "127.0.0.1:8088" {
		t.Fatalf("got %q", got)
	}
	if got := formatDisplayHostPort("10.0.0.5:6432"); got != "10.0.0.5:6432" {
		t.Fatalf("got %q", got)
	}
	if got := formatDisplayURL(":8088"); got != "http://127.0.0.1:8088" {
		t.Fatalf("got %q", got)
	}
	for _, lvl := range []string{"debug", "info", "warn", "error", "unknown"} {
		initLogger(lvl)
	}
	printUsage()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := demo.NewServer()
	addr, err := srv.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dsn := policy.BuildDSN(addr, "pgveil", "", "pgveil_demo", "cli-test", false)

	// Test runInit -> writes valid config -> test runValidate -> test runDiscover (table, yaml, json)
	outPath := filepath.Join(t.TempDir(), "init_pgveil.yaml")
	runInit([]string{"--dsn", dsn, "--output", outPath, "--sample-rows", "20"})
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("runInit did not write %s: %v", outPath, err)
	}
	runValidate([]string{"--config", outPath})
	runDiscover([]string{"--dsn", dsn, "--format", "table", "--sample-rows", "15"})
	runDiscover([]string{"--dsn", dsn, "--format", "yaml", "--sample-rows", "15"})
	runDiscover([]string{"--dsn", dsn, "--format", "json", "--sample-rows", "15"})
	runDiscover([]string{"--config", outPath, "--format", "yaml", "--sample-rows", "10"})

	// Test executeScan: allowed + RLS rewrite + PII text + blocked (exit code 2) + missing profile
	demoCfgPath := filepath.Join(t.TempDir(), "demo.yaml")
	if err := os.WriteFile(demoCfgPath, demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", addr), 0o600); err != nil {
		t.Fatal(err)
	}
	var scanOut bytes.Buffer
	code, err := executeScan([]string{"--config", demoCfgPath, "--profile", "tenant_tr", "--sql", "SELECT id, email FROM customers", "--text", "ayse@example.com 10000000146"}, &scanOut)
	if err != nil || code != 0 || !strings.Contains(scanOut.String(), `"rls_rewritten": true`) || !strings.Contains(scanOut.String(), `"masked_text"`) {
		t.Fatalf("executeScan allow/RLS failed: code=%d err=%v out=%s", code, err, scanOut.String())
	}
	scanOut.Reset()
	code, err = executeScan([]string{"--config", demoCfgPath, "--profile", "ai_agent", "--sql", "DROP TABLE customers"}, &scanOut)
	if err != nil || code != 2 {
		t.Fatalf("executeScan block expected code=2, got code=%d err=%v", code, err)
	}
	if _, err := executeScan([]string{"--config", demoCfgPath, "--profile", "no_such_profile"}, &scanOut); err == nil {
		t.Fatal("expected missing profile error")
	}

	// Test runMCPCtx with env var defaults (zero CLI flags)
	t.Setenv("PGVEIL_CONFIG", demoCfgPath)
	t.Setenv("PGVEIL_PROFILE", "tenant_tr")
	t.Setenv("PGVEIL_DSN", dsn)
	mcpIn := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	var mcpOut bytes.Buffer
	if err := runMCPCtx(ctx, nil, mcpIn, &mcpOut); err != nil {
		t.Fatalf("runMCPCtx failed: %v", err)
	}
	if !strings.Contains(mcpOut.String(), "pgveil") {
		t.Fatalf("unexpected runMCPCtx output: %s", mcpOut.String())
	}

	// Test runMCPCtx in standalone Streamable HTTP mode (--http 127.0.0.1:0)
	mcpHTTPCtx, mcpHTTPCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer mcpHTTPCancel()
	if err := runMCPCtx(mcpHTTPCtx, []string{"--config", demoCfgPath, "--http", "127.0.0.1:0"}, strings.NewReader(""), &mcpOut); err != nil {
		t.Fatalf("runMCPCtx --http failed: %v", err)
	}

	// Test runDemoCtx lifecycle (bind ephemeral ports, then cancel gracefully)
	demoCtx, demoCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer demoCancel()
	if err := runDemoCtx(demoCtx, []string{"--listen", "127.0.0.1:0", "--admin", "127.0.0.1:0", "--log-level", "error"}); err != nil {
		t.Fatalf("runDemoCtx failed: %v", err)
	}

	// Test runServeCtx lifecycle (bind ephemeral ports against demo upstream, then cancel gracefully)
	serveCtx, serveCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer serveCancel()
	if err := runServeCtx(serveCtx, []string{"--config", demoCfgPath, "--log-level", "error"}); err != nil {
		t.Fatalf("runServeCtx failed: %v", err)
	}
}
