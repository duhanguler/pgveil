package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/twmb/franz-go/pkg/kgo"
)

// AuditEvent is the canonical immutable record emitted for every PostgreSQL query inspected by pgveil.
type AuditEvent struct {
	EventID            string         `json:"event_id"`
	TraceID            string         `json:"trace_id,omitempty"`
	OccurredAt         time.Time      `json:"occurred_at"`
	ClientAddr         string         `json:"client_addr"`
	DBUser             string         `json:"db_user"`
	DatabaseName       string         `json:"database_name"`
	ApplicationName    string         `json:"application_name,omitempty"`
	RoleProfile        string         `json:"role_profile"`
	StatementType      string         `json:"statement_type"`
	SQLFingerprint      string         `json:"sql_fingerprint"`
	RawSQLPreview       string         `json:"raw_sql_preview"`
	RLSRewritten        bool           `json:"rls_rewritten,omitempty"`
	RLSRulesApplied     []string       `json:"rls_rules_applied,omitempty"`
	RewrittenSQLPreview string         `json:"rewritten_sql_preview,omitempty"`
	Decision            string         `json:"decision"` // ALLOW, MASKED, BLOCKED, TRUNCATED, HITL_APPROVED, HITL_DENIED, HITL_EXPIRED
	RiskLevel          string         `json:"risk_level"`
	PolicyRule         string         `json:"policy_rule"`
	PolicyReason       string         `json:"policy_reason,omitempty"`
	TablesAccessed     []string       `json:"tables_accessed,omitempty"`
	RowsReturned       int            `json:"rows_returned"`
	RowsTruncated      bool           `json:"rows_truncated"`
	PIIFieldsMasked    int            `json:"pii_fields_masked"`
	PIIEntities        map[string]int `json:"pii_entities,omitempty"`
	ProxyOverheadUs    int64          `json:"proxy_overhead_us"`
	UpstreamDurationUs int64          `json:"upstream_duration_us"`
}

// Summary aggregates live operational and security KPIs for the Control Plane dashboard.
type Summary struct {
	TotalQueries      int64            `json:"total_queries"`
	MaskedQueries     int64            `json:"masked_queries"`
	BlockedQueries    int64            `json:"blocked_queries"`
	TruncatedQueries  int64            `json:"truncated_queries"`
	HITLTriggered     int64            `json:"hitl_triggered"`
	TotalPIIFields    int64            `json:"total_pii_fields"`
	TotalRowsReturned int64            `json:"total_rows_returned"`
	AvgProxyOverhead  float64          `json:"avg_proxy_overhead_us"`
	KafkaEnabled      bool             `json:"kafka_enabled"`
	ByDecision        map[string]int64 `json:"by_decision"`
	ByRole            map[string]int64 `json:"by_role"`
	PIIByEntity       map[string]int64 `json:"pii_by_entity"`
	BlockedByRule     map[string]int64 `json:"blocked_by_rule"`
}

// Bus receives audit events non-blockingly, updates live stats, fans out SSE streams,
// and optionally publishes asynchronously to Apache Kafka / Redpanda.
type Bus struct {
	mu          sync.RWMutex
	ring        []AuditEvent
	capacity    int
	subscribers map[chan AuditEvent]struct{}

	// Aggregate counters
	totalQueries     int64
	maskedQueries    int64
	blockedQueries   int64
	truncatedQueries int64
	hitlTriggered    int64
	totalPIIFields   int64
	totalRows        int64
	sumOverheadUs    int64
	byDecision       map[string]int64
	byRole           map[string]int64
	piiByEntity      map[string]int64
	blockedByRule    map[string]int64

	// Async Kafka pipeline
	kafkaCfg    policy.KafkaConfig
	kafkaClient *kgo.Client
	kafkaCh     chan AuditEvent
	metrics     *telemetry.Metrics
	stopCh      chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup
}

// NewBus initializes the in-memory ring buffer, SSE hub, and optional Kafka producer.
func NewBus(capacity int, kafkaCfg policy.KafkaConfig, metrics *telemetry.Metrics) *Bus {
	if capacity <= 0 {
		capacity = 500
	}
	b := &Bus{
		ring:          make([]AuditEvent, 0, capacity),
		capacity:      capacity,
		subscribers:   make(map[chan AuditEvent]struct{}),
		byDecision:    make(map[string]int64),
		byRole:        make(map[string]int64),
		piiByEntity:   make(map[string]int64),
		blockedByRule: make(map[string]int64),
		kafkaCfg:      kafkaCfg,
		metrics:       metrics,
		stopCh:        make(chan struct{}),
	}

	if kafkaCfg.Enabled && len(kafkaCfg.Brokers) > 0 {
		cl, err := kgo.NewClient(
			kgo.SeedBrokers(kafkaCfg.Brokers...),
			kgo.ClientID(kafkaCfg.ClientID),
			kgo.AllowAutoTopicCreation(),
			kgo.ProducerBatchMaxBytes(1024*1024),
			kgo.ProduceRequestTimeout(5*time.Second),
		)
		if err != nil {
			slog.Warn("failed to initialize Kafka producer, continuing in local audit mode", "brokers", kafkaCfg.Brokers, "err", err)
		} else {
			b.kafkaClient = cl
			b.kafkaCh = make(chan AuditEvent, 4096)
			b.wg.Add(1)
			go b.kafkaLoop()
			slog.Info("kafka async audit producer enabled", "brokers", kafkaCfg.Brokers, "audit_topic", kafkaCfg.AuditTopic)
		}
	}
	return b
}

// Publish records an AuditEvent without blocking the PostgreSQL wire hot path.
func (b *Bus) Publish(ev AuditEvent) {
	if ev.EventID == "" {
		ev.EventID = newEventID()
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	if r := []rune(ev.RawSQLPreview); len(r) > 500 {
		ev.RawSQLPreview = string(r[:500]) + "..."
	}
	if r := []rune(ev.RewrittenSQLPreview); len(r) > 500 {
		ev.RewrittenSQLPreview = string(r[:500]) + "..."
	}

	b.mu.Lock()
	if len(b.ring) >= b.capacity {
		copy(b.ring, b.ring[1:])
		b.ring[len(b.ring)-1] = ev
	} else {
		b.ring = append(b.ring, ev)
	}
	b.totalQueries++
	b.totalRows += int64(ev.RowsReturned)
	b.totalPIIFields += int64(ev.PIIFieldsMasked)
	b.sumOverheadUs += ev.ProxyOverheadUs
	b.byDecision[ev.Decision]++
	b.byRole[ev.RoleProfile]++

	if ev.PIIFieldsMasked > 0 {
		b.maskedQueries++
	}
	if ev.RowsTruncated {
		b.truncatedQueries++
	}
	if ev.Decision == "BLOCKED" || ev.Decision == "HITL_DENIED" || ev.Decision == "HITL_EXPIRED" {
		b.blockedQueries++
		if ev.PolicyRule != "" {
			b.blockedByRule[ev.PolicyRule]++
		}
	}
	if ev.Decision == "HITL_APPROVED" || ev.Decision == "HITL_DENIED" || ev.Decision == "HITL_EXPIRED" {
		b.hitlTriggered++
	}
	for k, v := range ev.PIIEntities {
		b.piiByEntity[k] += int64(v)
	}

	for ch := range b.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}
	b.mu.Unlock()

	if b.kafkaCh != nil {
		select {
		case b.kafkaCh <- ev:
		default:
			if b.metrics != nil {
				b.metrics.KafkaPublished.WithLabelValues(b.kafkaCfg.AuditTopic, "dropped").Inc()
			}
		}
	}
}

func (b *Bus) kafkaLoop() {
	defer b.wg.Done()
	for {
		select {
		case <-b.stopCh:
			return
		case ev := <-b.kafkaCh:
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			rec := &kgo.Record{
				Topic: b.kafkaCfg.AuditTopic,
				Key:   []byte(ev.RoleProfile),
				Value: payload,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err = b.kafkaClient.ProduceSync(ctx, rec).FirstErr()
			cancel()
			if b.metrics != nil {
				if err != nil {
					b.metrics.KafkaPublished.WithLabelValues(b.kafkaCfg.AuditTopic, "error").Inc()
				} else {
					b.metrics.KafkaPublished.WithLabelValues(b.kafkaCfg.AuditTopic, "ok").Inc()
				}
			}

			// Emit high-severity security alert to dedicated alerts topic
			if ev.Decision == "BLOCKED" || ev.Decision == "HITL_DENIED" || ev.RowsTruncated || ev.RiskLevel == "CRITICAL" {
				alertRec := &kgo.Record{
					Topic: b.kafkaCfg.AlertsTopic,
					Key:   []byte(ev.RoleProfile),
					Value: payload,
				}
				actx, acancel := context.WithTimeout(context.Background(), 3*time.Second)
				aerr := b.kafkaClient.ProduceSync(actx, alertRec).FirstErr()
				acancel()
				if b.metrics != nil {
					if aerr != nil {
						b.metrics.KafkaPublished.WithLabelValues(b.kafkaCfg.AlertsTopic, "error").Inc()
					} else {
						b.metrics.KafkaPublished.WithLabelValues(b.kafkaCfg.AlertsTopic, "ok").Inc()
					}
				}
			}
		}
	}
}

// Recent returns up to limit audit events ordered newest-first.
func (b *Bus) Recent(limit int, decisionFilter, roleFilter string) []AuditEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if limit <= 0 || limit > b.capacity {
		limit = 100
	}
	out := make([]AuditEvent, 0, min(limit, len(b.ring)))
	for i := len(b.ring) - 1; i >= 0 && len(out) < limit; i-- {
		ev := b.ring[i]
		if decisionFilter != "" && ev.Decision != decisionFilter {
			continue
		}
		if roleFilter != "" && ev.RoleProfile != roleFilter {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// Summary returns an immutable snapshot of aggregate metrics.
func (b *Bus) Summary() Summary {
	b.mu.RLock()
	defer b.mu.RUnlock()
	avg := 0.0
	if b.totalQueries > 0 {
		avg = float64(b.sumOverheadUs) / float64(b.totalQueries)
	}
	return Summary{
		TotalQueries:      b.totalQueries,
		MaskedQueries:     b.maskedQueries,
		BlockedQueries:    b.blockedQueries,
		TruncatedQueries:  b.truncatedQueries,
		HITLTriggered:     b.hitlTriggered,
		TotalPIIFields:    b.totalPIIFields,
		TotalRowsReturned: b.totalRows,
		AvgProxyOverhead:  avg,
		KafkaEnabled:      b.kafkaClient != nil,
		ByDecision:        copyMap(b.byDecision),
		ByRole:            copyMap(b.byRole),
		PIIByEntity:       copyMap(b.piiByEntity),
		BlockedByRule:     copyMap(b.blockedByRule),
	}
}

// Subscribe creates an SSE subscription channel for real-time audit event streaming.
func (b *Bus) Subscribe() (<-chan AuditEvent, func()) {
	ch := make(chan AuditEvent, 64)
	b.mu.Lock()
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subscribers, ch)
		close(ch)
		b.mu.Unlock()
	}
}

// Close flushes and shuts down the async Kafka producer safely (idempotent).
func (b *Bus) Close() {
	b.closeOnce.Do(func() {
		close(b.stopCh)
		b.wg.Wait()
		if b.kafkaClient != nil {
			b.kafkaClient.Close()
		}
	})
}

func copyMap(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func newEventID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "evt_" + hex.EncodeToString(b[:])
}
