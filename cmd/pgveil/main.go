package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/duhanguler/pgveil/internal/api"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/proxy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/duhanguler/pgveil/internal/webui"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version = "0.1.0"
	commit  = "dev"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
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
	fmt.Println(`pgveil — Zero-Trust PostgreSQL Wire-Protocol PII Masking & AI-Agent SQL Firewall Proxy

Usage:
  pgveil serve    [--config configs/pgveil.yaml] [--log-level info]
  pgveil validate [--config configs/pgveil.yaml]
  pgveil scan     --sql "SELECT ..." [--profile ai_agent] [--config configs/pgveil.yaml]
  pgveil version`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/pgveil.yaml", "Path to pgveil YAML configuration file")
	logLevel := fs.String("log-level", "info", "Log level (debug, info, warn, error)")
	_ = fs.Parse(args)

	initLogger(*logLevel)

	policyMgr, err := policy.LoadFile(*cfgPath)
	if err != nil {
		slog.Error("failed to load configuration", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	cfg := policyMgr.Config()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Live hot-reload on SIGHUP
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
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
		slog.Error("failed to initialize wire proxy", "err", err)
		os.Exit(1)
	}

	distFS, err := webui.DistFS()
	if err != nil {
		slog.Warn("embedded web UI unavailable", "err", err)
	}

	apiSrv := api.NewServer(policyMgr, hitlMgr, eventBus, wireProxy.Addr, reg, distFS, version)
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
	case err := <-errCh:
		slog.Error("fatal server error", "err", err)
		stop()
		os.Exit(1)
	}
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
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/pgveil.yaml", "Path to pgveil YAML configuration file")
	sqlQuery := fs.String("sql", "", "SQL query to inspect against the AST firewall")
	profileName := fs.String("profile", "ai_agent", "Role profile name")
	sampleText := fs.String("text", "", "Optional sample text to scan with PII compliance packs")
	_ = fs.Parse(args)

	mgr, err := policy.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	prof, ok := mgr.GetProfileByName(*profileName)
	if !ok {
		fmt.Fprintf(os.Stderr, "profile %q not found\n", *profileName)
		os.Exit(1)
	}

	out := map[string]any{"profile": prof.Name}
	exitCode := 0
	if *sqlQuery != "" {
		dec := firewall.Evaluate(*sqlQuery, prof)
		out["firewall_decision"] = dec
		if dec.Action == firewall.ActionBlock {
			exitCode = 2
		}
	}
	if *sampleText != "" {
		masked, counts := mgr.Masker().MaskText(*sampleText, prof.EnabledEntities())
		out["masked_text"] = masked
		out["pii_entities"] = counts
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
	os.Exit(exitCode)
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
