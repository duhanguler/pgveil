package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/duhanguler/pgveil/internal/events"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/twmb/franz-go/pkg/kgo"
)

type workerConfig struct {
	brokers        []string
	auditTopic     string
	alertsTopic    string
	dlqTopic       string
	groupID        string
	databaseURL    string
	metricsAddr    string
	webhookURL     string
	batchSize      int
	flushInterval  time.Duration
	burstThreshold int
	burstWindow    time.Duration
}

type burstTracker struct {
	mu        sync.Mutex
	counts    map[string][]time.Time
	threshold int
	window    time.Duration
}

func newBurstTracker(threshold int, window time.Duration) *burstTracker {
	return &burstTracker{
		counts:    make(map[string][]time.Time),
		threshold: threshold,
		window:    window,
	}
}

func (bt *burstTracker) RecordBlocked(role string, now time.Time) (triggered bool, count int) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	cutoff := now.Add(-bt.window)
	hist := bt.counts[role]
	kept := hist[:0]
	for _, ts := range hist {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	bt.counts[role] = kept
	return len(kept) == bt.threshold, len(kept)
}

func main() {
	fs := flag.NewFlagSet("audit-worker", flag.ExitOnError)
	brokersStr := fs.String("brokers", envOr("PGVEIL_KAFKA_BROKERS", "localhost:9092"), "Comma-separated Kafka brokers")
	auditTopic := fs.String("audit-topic", envOr("PGVEIL_KAFKA_AUDIT_TOPIC", "pgveil.audit.queries"), "Kafka audit topic")
	alertsTopic := fs.String("alerts-topic", envOr("PGVEIL_KAFKA_ALERTS_TOPIC", "pgveil.alerts.security"), "Kafka alerts topic")
	dlqTopic := fs.String("dlq-topic", envOr("PGVEIL_KAFKA_DLQ_TOPIC", "pgveil.audit.dlq"), "Kafka dead-letter topic")
	groupID := fs.String("group-id", envOr("PGVEIL_KAFKA_GROUP", "pgveil-audit-sink"), "Kafka consumer group ID")
	dbURL := fs.String("database-url", envOr("PGVEIL_DATABASE_URL", "postgres://pgveil:pgveil_dev_password@localhost:5432/pgveil_demo?sslmode=disable"), "PostgreSQL audit sink DSN")
	metricsAddr := fs.String("metrics-addr", envOr("PGVEIL_WORKER_ADDR", ":8089"), "HTTP /metrics and /healthz listen addr")
	webhookURL := fs.String("webhook-url", envOr("PGVEIL_ALERT_WEBHOOK", ""), "Optional Slack/Teams/Webhook URL for burst anomaly alerts")
	_ = fs.Parse(os.Args[1:])

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := workerConfig{
		brokers:        splitCSV(*brokersStr),
		auditTopic:     *auditTopic,
		alertsTopic:    *alertsTopic,
		dlqTopic:       *dlqTopic,
		groupID:        *groupID,
		databaseURL:    *dbURL,
		metricsAddr:    *metricsAddr,
		webhookURL:     *webhookURL,
		batchSize:      50,
		flushInterval:  2 * time.Second,
		burstThreshold: 5,
		burstWindow:    60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	reg := prometheus.NewRegistry()
	f := promauto.With(reg)
	consumedTotal := f.NewCounterVec(prometheus.CounterOpts{
		Name: "pgveil_worker_consumed_total",
		Help: "Kafka messages consumed by pgveil-audit-worker.",
	}, []string{"topic", "status"})
	batchesFlushed := f.NewCounter(prometheus.CounterOpts{
		Name: "pgveil_worker_db_batches_total",
		Help: "Batch inserts persisted to pgveil_audit_log.",
	})
	anomaliesTotal := f.NewCounterVec(prometheus.CounterOpts{
		Name: "pgveil_worker_anomalies_total",
		Help: "Burst security anomalies detected by pgveil-audit-worker.",
	}, []string{"role"})

	// Expose /healthz and /metrics
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"pgveil-audit-worker"}`))
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	httpSrv := &http.Server{Addr: cfg.metricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		slog.Info("audit-worker metrics listening", "addr", cfg.metricsAddr)
		_ = httpSrv.ListenAndServe()
	}()

	pool, err := connectPoolWithRetry(ctx, cfg.databaseURL)
	if err != nil {
		slog.Error("unable to connect to PostgreSQL audit sink", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	kafkaClient, err := kgo.NewClient(
		kgo.SeedBrokers(cfg.brokers...),
		kgo.ConsumerGroup(cfg.groupID),
		kgo.ConsumeTopics(cfg.auditTopic, cfg.alertsTopic),
		kgo.AllowAutoTopicCreation(),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		slog.Error("failed to initialize Kafka consumer", "brokers", cfg.brokers, "err", err)
		os.Exit(1)
	}
	defer kafkaClient.Close()

	slog.Info("pgveil-audit-worker started",
		"brokers", cfg.brokers,
		"topics", []string{cfg.auditTopic, cfg.alertsTopic},
		"group", cfg.groupID,
	)

	tracker := newBurstTracker(cfg.burstThreshold, cfg.burstWindow)
	var batch []events.AuditEvent
	flushTicker := time.NewTicker(cfg.flushInterval)
	defer flushTicker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := persistBatch(ctx, pool, batch); err != nil {
			slog.Error("batch persist to pgveil_audit_log failed", "count", len(batch), "err", err)
			return
		}
		batchesFlushed.Inc()
		if err := kafkaClient.CommitUncommittedOffsets(ctx); err != nil {
			slog.Warn("kafka offset commit warning", "err", err)
		}
		slog.Info("persisted audit batch", "rows", len(batch))
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = httpSrv.Shutdown(shutCtx)
			cancel()
			return
		case <-flushTicker.C:
			flush()
		default:
			pollCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			fetches := kafkaClient.PollFetches(pollCtx)
			cancel()
			if fetches.IsClientClosed() {
				return
			}
			fetches.EachRecord(func(rec *kgo.Record) {
				var ev events.AuditEvent
				if err := json.Unmarshal(rec.Value, &ev); err != nil {
					consumedTotal.WithLabelValues(rec.Topic, "dlq").Inc()
					sendDLQ(ctx, kafkaClient, cfg.dlqTopic, rec, err)
					return
				}
				consumedTotal.WithLabelValues(rec.Topic, "ok").Inc()

				if rec.Topic == cfg.alertsTopic {
					if triggered, count := tracker.RecordBlocked(ev.RoleProfile, time.Now()); triggered {
						anomaliesTotal.WithLabelValues(ev.RoleProfile).Inc()
						slog.Warn("SECURITY BURST ANOMALY DETECTED",
							"role", ev.RoleProfile,
							"blocked_count", count,
							"window", cfg.burstWindow.String(),
							"latest_rule", ev.PolicyRule,
						)
						if cfg.webhookURL != "" {
							fireWebhook(cfg.webhookURL, ev, count)
						}
					}
					return
				}

				batch = append(batch, ev)
				if len(batch) >= cfg.batchSize {
					flush()
				}
			})
		}
	}
}

func persistBatch(ctx context.Context, pool *pgxpool.Pool, items []events.AuditEvent) error {
	b := &pgx.Batch{}
	const q = `INSERT INTO pgveil_audit_log (
		event_id, trace_id, occurred_at, client_addr, db_user, database_name,
		application_name, role_profile, statement_type, sql_fingerprint, raw_sql_preview,
		decision, policy_reason, tables_accessed, rows_returned, rows_truncated,
		pii_fields_masked, pii_entities, proxy_overhead_us, upstream_duration_us
	) VALUES (
		$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20
	) ON CONFLICT (event_id) DO NOTHING`

	for _, ev := range items {
		piiJSON, _ := json.Marshal(ev.PIIEntities)
		b.Queue(q,
			ev.EventID, ev.TraceID, ev.OccurredAt, ev.ClientAddr, ev.DBUser, ev.DatabaseName,
			ev.ApplicationName, ev.RoleProfile, ev.StatementType, ev.SQLFingerprint, ev.RawSQLPreview,
			ev.Decision, ev.PolicyReason, ev.TablesAccessed, ev.RowsReturned, ev.RowsTruncated,
			ev.PIIFieldsMasked, piiJSON, ev.ProxyOverheadUs, ev.UpstreamDurationUs,
		)
	}
	br := pool.SendBatch(ctx, b)
	defer br.Close()
	for range items {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func sendDLQ(ctx context.Context, cl *kgo.Client, dlqTopic string, orig *kgo.Record, parseErr error) {
	envelope, _ := json.Marshal(map[string]any{
		"source_topic": orig.Topic,
		"partition":    orig.Partition,
		"offset":       orig.Offset,
		"error":        parseErr.Error(),
		"raw_payload":  string(orig.Value),
		"failed_at":    time.Now().UTC(),
	})
	dlqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = cl.ProduceSync(dlqCtx, &kgo.Record{Topic: dlqTopic, Value: envelope}).FirstErr()
}

func fireWebhook(url string, ev events.AuditEvent, count int) {
	body, _ := json.Marshal(map[string]any{
		"text": fmt.Sprintf("[pgveil ALERT] Burst anomaly: %d blocked queries for profile %q (latest rule: %s)", count, ev.RoleProfile, ev.PolicyRule),
	})
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
	}
}

func connectPoolWithRetry(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	var lastErr error
	for attempt := 1; attempt <= 15; attempt++ {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			if pingErr := pool.Ping(ctx); pingErr == nil {
				return pool, nil
			} else {
				lastErr = pingErr
				pool.Close()
			}
		} else {
			lastErr = err
		}
		slog.Info("waiting for PostgreSQL audit sink...", "attempt", attempt)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, lastErr
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
