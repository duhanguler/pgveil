package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/duhanguler/pgveil/internal/api"
	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/discover"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/mcpserver"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/proxy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/duhanguler/pgveil/internal/webui"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version = "0.5.1"
	commit  = "dev"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}
	switch os.Args[1] {
	case "demo":
		runDemo(os.Args[2:])
	case "init":
		runInit(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "discover":
		runDiscover(os.Args[2:])
	case "mcp":
		runMCP(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("pgveil %s (%s)\n", version, commit)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`pgveil — Zero-Trust PostgreSQL Wire-Protocol PII Masking, Virtual RLS & AI-Agent SQL Firewall Proxy

Usage:
  pgveil demo     [--listen :6432] [--admin :8088] [--log-level info]
  pgveil init     --dsn postgres://... [--output pgveil.yaml] [--sample-rows 50] [--force]
  pgveil serve    [--config configs/pgveil.yaml] [--log-level info]
  pgveil discover [--dsn postgres://...] [--config configs/pgveil.yaml] [--format table|yaml|json] [--sample-rows 50]
  pgveil mcp      [--config configs/pgveil.yaml] [--profile ai_agent] [--dsn postgres://...] [--http :8090]
  pgveil scan     --sql "SELECT ..." [--profile ai_agent] [--config configs/pgveil.yaml]
  pgveil validate [--config configs/pgveil.yaml]
  pgveil version`)
}

func runDemo(args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runDemoCtx(ctx, args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func runDemoCtx(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	listenAddr := fs.String("listen", ":6432", "Wire proxy listen address")
	adminAddr := fs.String("admin", ":8088", "Web Console & Control Plane HTTP address")
	logLevel := fs.String("log-level", "warn", "Log level (debug, info, warn, error)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	initLogger(*logLevel)

	demoPG := demo.NewServer()
	upstreamAddr, err := demoPG.Start(ctx, "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start embedded demo PostgreSQL backend: %w", err)
	}

	policyMgr, err := policy.LoadBytes(demo.BuildDemoConfigYAML(*listenAddr, *adminAddr, upstreamAddr))
	if err != nil {
		return fmt.Errorf("failed to compile demo configuration: %w", err)
	}
	cfg := policyMgr.Config()

	reg := prometheus.NewRegistry()
	metrics := telemetry.NewMetrics(reg)
	tracer, shutdownTracer := telemetry.InitTracer(ctx, cfg.Telemetry.ServiceName, false, "")
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = shutdownTracer(sctx)
	}()

	hitlMgr := hitl.NewManager(250)
	eventBus := events.NewBus(500, cfg.Kafka, metrics)
	defer eventBus.Close()

	wireProxy, err := proxy.NewServer(policyMgr, hitlMgr, eventBus, metrics, tracer)
	if err != nil {
		return fmt.Errorf("failed to initialize wire proxy: %w", err)
	}

	distFS, _ := webui.DistFS()
	apiSrv := api.NewServer(policyMgr, hitlMgr, eventBus, wireProxy.Addr, reg, distFS, version).
		AttachRuntime(wireProxy.CostRunner(), wireProxy.ChatOps(), metrics)
	defer apiSrv.Close()
	httpSrv := &http.Server{
		Addr:              cfg.Server.AdminAddr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()
	go func() {
		if err := wireProxy.Start(ctx); err != nil {
			errCh <- fmt.Errorf("wire proxy: %w", err)
		}
	}()

	// Wait briefly for proxy listener to bind before printing banner
	deadline := time.Now().Add(2 * time.Second)
	for wireProxy.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	uiURL := formatDisplayURL(*adminAddr)
	wireHostPort := formatDisplayHostPort(*listenAddr)
	fmt.Printf(`
pgveil v%s — Interactive Zero-Config Sandbox (No Docker / No External PostgreSQL)
────────────────────────────────────────────────────────────────────────────────
  Web Workbench:   %s
  Streamable MCP:  %s/mcp  (Bearer token: pgv_demo_istanbul_tenant -> city='Istanbul')
  Wire Proxy:      %s  (backed by embedded PG16 demo engine on %s)
  Seeded Tables:   customers (40) · orders (8) · payments (5) · support_tickets (4) · api_secrets (3)

Try live from another terminal:
  # 1) AI-Agent masked PII + AST firewall + EXPLAIN Cost Guard:
  psql "postgres://pgveil@%s/pgveil_demo?sslmode=disable&application_name=ai_agent" \
       -c "SELECT id, full_name, email, tckn, city FROM customers LIMIT 5;"

  # 2) Remote Streamable HTTP MCP + JWT/Token Claim Virtual RLS ({{jwt.city}}):
  curl -s %s/mcp -H "Authorization: Bearer pgv_demo_istanbul_tenant" \
       -H "Content-Type: application/json" \
       -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT id, full_name, city, tckn FROM customers"}}}'

Press Ctrl+C to stop.
`, version, uiURL, uiURL, wireHostPort, upstreamAddr, wireHostPort, uiURL)

	select {
	case <-ctx.Done():
		fmt.Println("\nShutting down pgveil demo...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return fmt.Errorf("demo server error: %w", err)
	}
}

func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dsn := fs.String("dsn", "", "PostgreSQL connection URI to scan (required)")
	output := fs.String("output", "pgveil.yaml", "Output path for generated configuration file")
	sampleRows := fs.Int("sample-rows", 50, "Max non-null rows sampled per column during discovery")
	force := fs.Bool("force", false, "Overwrite output file if it already exists")
	_ = fs.Parse(args)

	if strings.TrimSpace(*dsn) == "" {
		fmt.Fprintln(os.Stderr, "error: --dsn is required (e.g. pgveil init --dsn postgres://user:pass@localhost:5432/mydb)")
		os.Exit(1)
	}
	if !*force {
		if _, err := os.Stat(*output); err == nil {
			fmt.Fprintf(os.Stderr, "error: %q already exists (pass --force to overwrite)\n", *output)
			os.Exit(1)
		}
	}

	fmt.Printf("Scanning PostgreSQL schema for PII & secrets (up to %d rows/column)...\n", *sampleRows)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := discover.Scan(ctx, *dsn, *sampleRows, "pgveil-init-preview")
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery failed: %v\n", err)
		os.Exit(1)
	}

	yml, err := discover.GenerateStarterConfig(report, *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to synthesize config: %v\n", err)
		os.Exit(1)
	}
	if _, err := policy.LoadBytes([]byte(yml)); err != nil {
		fmt.Fprintf(os.Stderr, "internal error: synthesized config failed validation: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, []byte(yml), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %q: %v\n", *output, err)
		os.Exit(1)
	}

	fmt.Printf("\nWrote %s (%d tables scanned, %d sensitive columns detected)\n", *output, report.TablesScanned, report.FindingsCount)
	if len(report.Findings) > 0 {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "\nTABLE.COLUMN\tRISK\tCOMPLIANCE\tSTRATEGY")
		fmt.Fprintln(tw, "------------\t----\t----------\t--------")
		for _, f := range report.Findings {
			fmt.Fprintf(tw, "%s.%s\t%s\t%s\t%s\n",
				f.Table, f.Column, f.RiskLevel, strings.ToUpper(strings.Join(f.CompliancePacks, ",")), f.RecommendedStrategy)
		}
		_ = tw.Flush()
	}
	fmt.Printf("\nNext steps:\n  1. Review %s (override secrets via PGVEIL_UPSTREAM_PASSWORD / PGVEIL_MASKING_SECRET)\n  2. Validate: pgveil validate --config %s\n  3. Run:      pgveil serve --config %s\n", *output, *output, *output)
}

func formatDisplayURL(addr string) string {
	return "http://" + formatDisplayHostPort(addr)
}

func formatDisplayHostPort(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		return "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	return addr
}

func runServe(args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runServeCtx(ctx, args); err != nil {
		slog.Error("fatal server error", "err", err)
		os.Exit(1)
	}
}

func runServeCtx(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "configs/pgveil.yaml", "Path to pgveil YAML configuration file")
	logLevel := fs.String("log-level", "info", "Log level (debug, info, warn, error)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	initLogger(*logLevel)

	policyMgr, err := policy.LoadFile(*cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration %q: %w", *cfgPath, err)
	}
	cfg := policyMgr.Config()

	// Live hot-reload on SIGHUP
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				if err := policyMgr.ReloadFile(); err != nil {
					slog.Error("SIGHUP policy reload failed", "err", err)
				} else {
					_, ver := policyMgr.RawYAML()
					slog.Info("policies hot-reloaded via SIGHUP", "version", ver)
				}
			}
		}
	}()

	reg := prometheus.NewRegistry()
	metrics := telemetry.NewMetrics(reg)
	tracer, shutdownTracer := telemetry.InitTracer(ctx, cfg.Telemetry.ServiceName, cfg.Telemetry.OTelEnabled, cfg.Telemetry.OTelEndpoint)
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = shutdownTracer(sctx)
	}()

	hitlMgr := hitl.NewManager(250)
	eventBus := events.NewBus(500, cfg.Kafka, metrics)
	defer eventBus.Close()

	wireProxy, err := proxy.NewServer(policyMgr, hitlMgr, eventBus, metrics, tracer)
	if err != nil {
		return fmt.Errorf("failed to initialize wire proxy: %w", err)
	}

	distFS, err := webui.DistFS()
	if err != nil {
		slog.Warn("embedded web UI unavailable", "err", err)
	}

	apiSrv := api.NewServer(policyMgr, hitlMgr, eventBus, wireProxy.Addr, reg, distFS, version).
		AttachRuntime(wireProxy.CostRunner(), wireProxy.ChatOps(), metrics)
	defer apiSrv.Close()
	httpSrv := &http.Server{
		Addr:              cfg.Server.AdminAddr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		slog.Info("pgveil Control Plane & Web Console listening",
			"admin_addr", cfg.Server.AdminAddr,
			"metrics", fmt.Sprintf("http://localhost%s/metrics", cfg.Server.AdminAddr),
		)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()
	go func() {
		if err := wireProxy.Start(ctx); err != nil {
			errCh <- fmt.Errorf("wire proxy: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down pgveil gracefully...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

func runDiscover(args []string) {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/pgveil.yaml", "Optional config file for default upstream DSN")
	dsn := fs.String("dsn", "", "PostgreSQL connection URI (overrides config)")
	sampleRows := fs.Int("sample-rows", 50, "Max non-null rows sampled per column")
	format := fs.String("format", "table", "Output format: table, yaml, or json")
	_ = fs.Parse(args)

	targetDSN := *dsn
	secret := "pgveil-discover-preview"
	if targetDSN == "" {
		mgr, err := policy.LoadFile(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "provide --dsn or valid --config: %v\n", err)
			os.Exit(1)
		}
		cfg := mgr.Config()
		secret = cfg.Security.MaskingSecret
		targetDSN = policy.BuildDSN(
			cfg.Server.UpstreamAddr,
			cfg.Server.UpstreamUser,
			cfg.Server.UpstreamPassword,
			cfg.Server.UpstreamDatabase,
			"pgveil-discover",
			cfg.Server.UpstreamTLS.Enabled,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := discover.Scan(ctx, targetDSN, *sampleRows, secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovery failed: %v\n", err)
		os.Exit(1)
	}

	switch strings.ToLower(*format) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	case "yaml":
		fmt.Println("# Auto-generated by pgveil discover (" + report.Database + ")")
		fmt.Print(report.GeneratedYAML)
	default:
		fmt.Printf("pgveil Schema PII Discovery — database=%q tables=%d columns=%d findings=%d\n\n",
			report.Database, report.TablesScanned, report.ColumnsScanned, report.FindingsCount)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "TABLE.COLUMN\tRISK\tCOMPLIANCE\tSTRATEGY\tSAMPLE MASKED")
		fmt.Fprintln(tw, "------------\t----\t----------\t--------\t-------------")
		for _, f := range report.Findings {
			fmt.Fprintf(tw, "%s.%s\t%s\t%s\t%s\t%s\n",
				f.Table, f.Column, f.RiskLevel, strings.ToUpper(strings.Join(f.CompliancePacks, ",")), f.RecommendedStrategy, f.SampleMasked)
		}
		_ = tw.Flush()
		if len(report.RecommendedTables) > 0 {
			fmt.Printf("\nRecommended denied_tables: %s\n", strings.Join(report.RecommendedTables, ", "))
		}
		fmt.Println("\nRun with --format yaml to emit a ready-to-paste pgveil.yaml policy block.")
	}
}

func runMCP(args []string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runMCPCtx(ctx, args, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func envOrDefault(keys []string, fallback string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return fallback
}

func runMCPCtx(ctx context.Context, args []string, r io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	cfgPath := fs.String("config", envOrDefault([]string{"PGVEIL_CONFIG"}, "configs/pgveil.yaml"), "Path to pgveil YAML configuration file (env: PGVEIL_CONFIG)")
	profileName := fs.String("profile", envOrDefault([]string{"PGVEIL_PROFILE"}, "ai_agent"), "Role profile enforced on MCP tool calls (env: PGVEIL_PROFILE)")
	dsn := fs.String("dsn", envOrDefault([]string{"PGVEIL_DSN", "DATABASE_URL"}, ""), "Optional PostgreSQL DSN override (env: PGVEIL_DSN or DATABASE_URL)")
	httpAddr := fs.String("http", envOrDefault([]string{"PGVEIL_MCP_HTTP"}, ""), "Optional address to serve Streamable HTTP MCP (e.g. :8090) instead of stdio (env: PGVEIL_MCP_HTTP)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mgr, err := policy.LoadFile(*cfgPath)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	srv := mcpserver.NewServer(mgr, *profileName, *dsn, version)
	defer srv.Close()

	if strings.TrimSpace(*httpAddr) != "" {
		mux := http.NewServeMux()
		mux.Handle("/mcp", srv.HTTPHandler())
		mux.HandleFunc("GET /healthz", func(hw http.ResponseWriter, _ *http.Request) {
			hw.Header().Set("Content-Type", "application/json")
			_, _ = hw.Write([]byte(`{"status":"ok","transport":"streamable-http"}`))
		})
		httpSrv := &http.Server{
			Addr:              *httpAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		errCh := make(chan error, 1)
		go func() {
			slog.Info("pgveil Streamable HTTP MCP server listening", "addr", *httpAddr, "endpoint", "/mcp")
			if lerr := httpSrv.ListenAndServe(); lerr != nil && lerr != http.ErrServerClosed {
				errCh <- lerr
			}
		}()
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(sctx)
			return nil
		case lerr := <-errCh:
			return fmt.Errorf("mcp http server error: %w", lerr)
		}
	}

	if err := srv.ServeStdio(ctx, r, w); err != nil {
		return fmt.Errorf("mcp stdio server error: %w", err)
	}
	return nil
}

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/pgveil.yaml", "Path to pgveil YAML configuration file")
	_ = fs.Parse(args)

	mgr, err := policy.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID configuration %q: %v\n", *cfgPath, err)
		os.Exit(1)
	}
	cfg := mgr.Config()
	fmt.Printf("OK: %s validated (%d profiles, default=%q, upstream=%s)\n",
		*cfgPath, len(cfg.Profiles), cfg.DefaultProfile, cfg.Server.UpstreamAddr)
}

func runScan(args []string) {
	code, err := executeScan(args, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func executeScan(args []string, w io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	cfgPath := fs.String("config", "configs/pgveil.yaml", "Path to pgveil YAML configuration file")
	sqlQuery := fs.String("sql", "", "SQL query to inspect against the AST firewall")
	profileName := fs.String("profile", "ai_agent", "Role profile name")
	sampleText := fs.String("text", "", "Optional sample text to scan with PII compliance packs")
	if err := fs.Parse(args); err != nil {
		return 1, err
	}

	mgr, err := policy.LoadFile(*cfgPath)
	if err != nil {
		return 1, fmt.Errorf("config error: %w", err)
	}
	prof, ok := mgr.GetProfileByName(*profileName)
	if !ok {
		return 1, fmt.Errorf("profile %q not found", *profileName)
	}

	out := map[string]any{"profile": prof.Name}
	exitCode := 0
	if *sqlQuery != "" {
		dec := firewall.Evaluate(*sqlQuery, prof)
		out["firewall_decision"] = dec
		if dec.Action == firewall.ActionBlock {
			exitCode = 2
		} else if len(prof.Firewall.RowFilters) > 0 {
			cfg := mgr.Config()
			if rlsRes, rerr := firewall.RewriteWithRLS(*sqlQuery, prof, firewall.SessionContext{
				DBUser:          cfg.Server.UpstreamUser,
				Database:        cfg.Server.UpstreamDatabase,
				ApplicationName: prof.Name,
				RoleProfile:     prof.Name,
			}); rerr == nil && rlsRes.Rewritten {
				out["rls_rewritten"] = true
				out["rewritten_sql"] = rlsRes.SQL
				out["rls_rules"] = rlsRes.RulesApplied
			}
		}
	}
	if *sampleText != "" {
		masked, counts := mgr.Masker().MaskText(*sampleText, prof.EnabledEntities())
		out["masked_text"] = masked
		out["pii_entities"] = counts
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	return exitCode, nil
}

func initLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}
