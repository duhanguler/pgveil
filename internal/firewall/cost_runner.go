package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CostVerdict summarizes the result of a sideband EXPLAIN (FORMAT JSON) Cost Guard evaluation.
type CostVerdict struct {
	Evaluated bool
	CacheHit  bool
	Fallback  bool
	Blocked   bool
	Rule      string
	Reason    string
	Metrics   *PlanMetrics
}

// CostRunner executes non-invasive EXPLAIN (FORMAT JSON) pre-flight checks over a bounded,
// read-only sideband pgxpool backed by a TTL LRU PlanCache.
// Running EXPLAIN out-of-band avoids mutating client wire portals, preserves Flush ('H') pipelines,
// and works safely even when the client session is inside an open transaction (txStatus == 'T').
type CostRunner struct {
	policyMgr   *policy.Manager
	dsnOverride string
	cache       *PlanCache

	mu      sync.Mutex
	pool    *pgxpool.Pool
	poolDSN string
}

func NewCostRunner(policyMgr *policy.Manager, dsnOverride string) *CostRunner {
	return &CostRunner{
		policyMgr:   policyMgr,
		dsnOverride: dsnOverride,
		cache:       NewPlanCache(2048, 60*time.Second),
	}
}

func (r *CostRunner) resolveDSN() string {
	if r.dsnOverride != "" {
		return r.dsnOverride
	}
	cfg := r.policyMgr.Config()
	return policy.BuildDSN(
		cfg.Server.UpstreamAddr,
		cfg.Server.UpstreamUser,
		cfg.Server.UpstreamPassword,
		cfg.Server.UpstreamDatabase,
		"pgveil-cost-guard",
		cfg.Server.UpstreamTLS.Enabled,
	)
}

func (r *CostRunner) getPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := r.resolveDSN()
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pool != nil && r.poolDSN == dsn {
		return r.pool, nil
	}
	if r.pool != nil {
		r.pool.Close()
		r.pool = nil
	}

	pcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pcfg.MaxConns = 4
	pcfg.MinConns = 0
	pcfg.MaxConnIdleTime = 2 * time.Minute
	pcfg.ConnConfig.ConnectTimeout = 2 * time.Second
	// Use Simple Protocol so embedded demo engine & connection poolers (PgBouncer transaction mode) work seamlessly.
	pcfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pcfg.AfterConnect = func(cctx context.Context, conn *pgx.Conn) error {
		_, _ = conn.Exec(cctx, "SET default_transaction_read_only = on")
		_, _ = conn.Exec(cctx, "SET statement_timeout = '500ms'")
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, err
	}
	r.pool = pool
	r.poolDSN = dsn
	return pool, nil
}

// Close releases any pooled sideband PostgreSQL connections.
func (r *CostRunner) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pool != nil {
		r.pool.Close()
		r.pool = nil
	}
}

// Check evaluates sql (post-Virtual-RLS rewrite) against profile.Firewall.CostGuard.
func (r *CostRunner) Check(ctx context.Context, sql string, fingerprint string, rlsRules []string, profile *policy.RoleProfile) CostVerdict {
	if r == nil || profile == nil || !profile.Firewall.CostGuard.Enabled {
		return CostVerdict{}
	}
	cg := profile.Firewall.CostGuard
	explainable, hasParams := ClassifyForCostGuard(sql)
	if !explainable {
		return CostVerdict{}
	}

	policyVer := int64(1)
	if r.policyMgr != nil {
		policyVer = r.policyMgr.Version()
	}
	cacheKey := ""
	if fingerprint != "" && fingerprint != "unparseable" {
		cacheKey = BuildPlanCacheKey(profile.Name, policyVer, fingerprint, rlsRules)
		if cached, ok := r.cache.Get(cacheKey); ok {
			blocked, rule, reason := EvaluateCostGuard(&cached, cg)
			return CostVerdict{
				Evaluated: true,
				CacheHit:  true,
				Blocked:   blocked,
				Rule:      rule,
				Reason:    reason,
				Metrics:   &cached,
			}
		}
	}

	ectx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()

	pool, err := r.getPool(ectx)
	if err != nil {
		return r.handleExplainError("connect sideband EXPLAIN pool", err, cg)
	}

	explainSQL := "EXPLAIN (FORMAT JSON) " + sql
	if hasParams {
		explainSQL = "EXPLAIN (FORMAT JSON, GENERIC_PLAN) " + sql
	}

	rows, err := pool.Query(ectx, explainSQL)
	if err != nil {
		return r.handleExplainError("execute EXPLAIN", err, cg)
	}
	var sb strings.Builder
	for rows.Next() {
		var line string
		if sErr := rows.Scan(&line); sErr == nil {
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
	}
	qErr := rows.Err()
	rows.Close()
	if qErr != nil {
		return r.handleExplainError("read EXPLAIN plan", qErr, cg)
	}

	pm, pErr := ParseExplainJSON(sb.String())
	if pErr != nil {
		return r.handleExplainError("decode EXPLAIN JSON", pErr, cg)
	}

	if cacheKey != "" {
		r.cache.Put(cacheKey, *pm)
	}
	blocked, rule, reason := EvaluateCostGuard(pm, cg)
	return CostVerdict{
		Evaluated: true,
		CacheHit:  false,
		Blocked:   blocked,
		Rule:      rule,
		Reason:    reason,
		Metrics:   pm,
	}
}

func (r *CostRunner) handleExplainError(stage string, err error, cg policy.CostGuardPolicy) CostVerdict {
	slog.Warn("cost_guard EXPLAIN pre-flight unavailable", "stage", stage, "fail_closed", cg.FailClosed, "err", err)
	if cg.FailClosed {
		return CostVerdict{
			Evaluated: true,
			Fallback:  true,
			Blocked:   true,
			Rule:      "cost_guard_explain_failed",
			Reason:    fmt.Sprintf("Cost guard fail-closed: %s failed (%v)", stage, err),
		}
	}
	return CostVerdict{
		Evaluated: true,
		Fallback:  true,
		Blocked:   false,
	}
}
