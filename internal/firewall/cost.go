package firewall

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/duhanguler/pgveil/internal/policy"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// PlanMetrics captures query planner estimates extracted from EXPLAIN (FORMAT JSON).
type PlanMetrics struct {
	TotalCost     float64  `json:"total_cost"`
	PlanRows      int64    `json:"plan_rows"`
	SeqScanTables []string `json:"seq_scan_tables,omitempty"`
}

// InspectExplainPlanOnly validates an EXPLAIN query using PostgreSQL 17's C AST parser,
// ensuring it is a single plan-only EXPLAIN statement without ANALYZE execution side effects.
func InspectExplainPlanOnly(sql string) (string, error) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return "", errors.New("sql parameter is required")
	}
	if strings.IndexByte(trimmed, 0) >= 0 {
		return "", errors.New("sql contains invalid NUL byte")
	}

	candidate := trimmed
	tree, err := pg_query.Parse(candidate)
	if err != nil {
		// Callers of explain_query may pass options+query without leading EXPLAIN (e.g. "ANALYZE SELECT 1")
		candidate = "EXPLAIN " + trimmed
		var err2 error
		tree, err2 = pg_query.Parse(candidate)
		if err2 != nil {
			return "", fmt.Errorf("invalid SQL syntax: %w", err)
		}
	}
	if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		return "", errors.New("explain_query requires a single SQL statement")
	}
	if tree.Stmts[0].Stmt.GetExplainStmt() == nil {
		candidate = "EXPLAIN " + trimmed
		tree, err = pg_query.Parse(candidate)
		if err != nil || len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
			return "", fmt.Errorf("failed to construct EXPLAIN statement: %v", err)
		}
	}

	exp := tree.Stmts[0].Stmt.GetExplainStmt()
	if exp == nil {
		return "", errors.New("statement is not a valid EXPLAIN query")
	}
	for _, opt := range exp.Options {
		de := opt.GetDefElem()
		if de == nil {
			continue
		}
		if strings.EqualFold(de.Defname, "analyze") {
			// Bare ANALYZE (Arg == nil) or ANALYZE true/on/1 executes the statement; allow only explicit false/off/0.
			if de.Arg == nil {
				return "", errors.New("BLOCKED by pgveil: explain_query is plan-only and disallows EXPLAIN ANALYZE")
			}
			isFalse := false
			if b := de.Arg.GetBoolean(); b != nil && !b.Boolval {
				isFalse = true
			} else if s := de.Arg.GetString_(); s != nil && (strings.EqualFold(s.Sval, "false") || strings.EqualFold(s.Sval, "off") || s.Sval == "0") {
				isFalse = true
			} else if iv := de.Arg.GetInteger(); iv != nil && iv.Ival == 0 {
				isFalse = true
			}
			if !isFalse {
				return "", errors.New("BLOCKED by pgveil: explain_query is plan-only and disallows EXPLAIN ANALYZE")
			}
		}
	}
	return candidate, nil
}

// ExplainTarget represents an individual explainable SQL statement extracted for Cost Guard evaluation.
type ExplainTarget struct {
	SQL       string
	HasParams bool
}

// ExtractExplainTargets parses sql using PG17's C AST parser and extracts every explainable data
// statement (SELECT / UPDATE / DELETE / MERGE), including multi-statement Simple Queries so an
// expensive query can never bypass Cost Guard by appending "; SELECT 1".
func ExtractExplainTargets(sql string) []ExplainTarget {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || trimmed == ";" || strings.IndexByte(trimmed, 0) >= 0 {
		return nil
	}
	tree, err := pg_query.Parse(trimmed)
	if err != nil || len(tree.Stmts) == 0 {
		return nil
	}
	if len(tree.Stmts) == 1 {
		root := tree.Stmts[0].Stmt
		if root == nil || !isExplainableNode(root) {
			return nil
		}
		return []ExplainTarget{{
			SQL:       trimmed,
			HasParams: containsParamRef(root, 0),
		}}
	}
	targets := make([]ExplainTarget, 0, len(tree.Stmts))
	for _, raw := range tree.Stmts {
		if raw == nil || raw.Stmt == nil || !isExplainableNode(raw.Stmt) {
			continue
		}
		dep, derr := pg_query.Deparse(&pg_query.ParseResult{
			Version: tree.Version,
			Stmts:   []*pg_query.RawStmt{{Stmt: raw.Stmt}},
		})
		if derr != nil || strings.TrimSpace(dep) == "" {
			continue
		}
		targets = append(targets, ExplainTarget{
			SQL:       dep,
			HasParams: containsParamRef(raw.Stmt, 0),
		})
	}
	return targets
}

func isExplainableNode(root *pg_query.Node) bool {
	switch root.Node.(type) {
	case *pg_query.Node_SelectStmt,
		*pg_query.Node_UpdateStmt,
		*pg_query.Node_DeleteStmt,
		*pg_query.Node_MergeStmt:
		return true
	default:
		return false
	}
}

// ClassifyForCostGuard determines via PG17 AST whether sql is a single explainable data statement
// (SELECT / UPDATE / DELETE / MERGE) and whether it contains positional parameter refs ($1, $2).
func ClassifyForCostGuard(sql string) (explainable bool, hasParams bool) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || trimmed == ";" || strings.IndexByte(trimmed, 0) >= 0 {
		return false, false
	}
	tree, err := pg_query.Parse(trimmed)
	if err != nil || len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		return false, false
	}
	root := tree.Stmts[0].Stmt
	if !isExplainableNode(root) {
		return false, false
	}
	return true, containsParamRef(root, 0)
}

func containsParamRef(n *pg_query.Node, depth int) bool {
	if n == nil || depth > maxASTDepth {
		return false
	}
	d := depth + 1
	switch x := n.Node.(type) {
	case *pg_query.Node_ParamRef:
		return true
	case *pg_query.Node_SelectStmt:
		s := x.SelectStmt
		if s.WithClause != nil {
			for _, cte := range s.WithClause.Ctes {
				if containsParamRef(cte, d) {
					return true
				}
			}
		}
		for _, tl := range s.TargetList {
			if containsParamRef(tl, d) {
				return true
			}
		}
		for _, fc := range s.FromClause {
			if containsParamRef(fc, d) {
				return true
			}
		}
		if containsParamRef(s.WhereClause, d) || containsParamRef(s.HavingClause, d) ||
			containsParamRef(s.LimitCount, d) || containsParamRef(s.LimitOffset, d) {
			return true
		}
		for _, g := range s.GroupClause {
			if containsParamRef(g, d) {
				return true
			}
		}
		for _, vl := range s.ValuesLists {
			if containsParamRef(vl, d) {
				return true
			}
		}
		if s.Larg != nil && containsParamRef(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Larg}}, d) {
			return true
		}
		if s.Rarg != nil && containsParamRef(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Rarg}}, d) {
			return true
		}
	case *pg_query.Node_UpdateStmt:
		u := x.UpdateStmt
		if containsParamRef(u.WhereClause, d) {
			return true
		}
		for _, t := range u.TargetList {
			if containsParamRef(t, d) {
				return true
			}
		}
		for _, fc := range u.FromClause {
			if containsParamRef(fc, d) {
				return true
			}
		}
	case *pg_query.Node_DeleteStmt:
		if containsParamRef(x.DeleteStmt.WhereClause, d) {
			return true
		}
		for _, u := range x.DeleteStmt.UsingClause {
			if containsParamRef(u, d) {
				return true
			}
		}
	case *pg_query.Node_MergeStmt:
		if containsParamRef(x.MergeStmt.JoinCondition, d) || containsParamRef(x.MergeStmt.SourceRelation, d) {
			return true
		}
	case *pg_query.Node_CommonTableExpr:
		return containsParamRef(x.CommonTableExpr.Ctequery, d)
	case *pg_query.Node_JoinExpr:
		return containsParamRef(x.JoinExpr.Larg, d) || containsParamRef(x.JoinExpr.Rarg, d) || containsParamRef(x.JoinExpr.Quals, d)
	case *pg_query.Node_RangeSubselect:
		return containsParamRef(x.RangeSubselect.Subquery, d)
	case *pg_query.Node_ResTarget:
		return containsParamRef(x.ResTarget.Val, d)
	case *pg_query.Node_BoolExpr:
		for _, a := range x.BoolExpr.Args {
			if containsParamRef(a, d) {
				return true
			}
		}
	case *pg_query.Node_AExpr:
		return containsParamRef(x.AExpr.Lexpr, d) || containsParamRef(x.AExpr.Rexpr, d)
	case *pg_query.Node_FuncCall:
		for _, a := range x.FuncCall.Args {
			if containsParamRef(a, d) {
				return true
			}
		}
	case *pg_query.Node_TypeCast:
		return containsParamRef(x.TypeCast.Arg, d)
	case *pg_query.Node_SubLink:
		return containsParamRef(x.SubLink.Testexpr, d) || containsParamRef(x.SubLink.Subselect, d)
	case *pg_query.Node_CoalesceExpr:
		for _, a := range x.CoalesceExpr.Args {
			if containsParamRef(a, d) {
				return true
			}
		}
	case *pg_query.Node_CaseExpr:
		if containsParamRef(x.CaseExpr.Arg, d) || containsParamRef(x.CaseExpr.Defresult, d) {
			return true
		}
		for _, w := range x.CaseExpr.Args {
			if containsParamRef(w, d) {
				return true
			}
		}
	case *pg_query.Node_CaseWhen:
		return containsParamRef(x.CaseWhen.Expr, d) || containsParamRef(x.CaseWhen.Result, d)
	case *pg_query.Node_List:
		for _, it := range x.List.Items {
			if containsParamRef(it, d) {
				return true
			}
		}
	}
	return false
}

type explainJSONWrapper struct {
	Plan explainJSONNode `json:"Plan"`
}

type explainJSONNode struct {
	NodeType     string            `json:"Node Type"`
	RelationName string            `json:"Relation Name"`
	Schema       string            `json:"Schema"`
	TotalCost    float64           `json:"Total Cost"`
	PlanRows     float64           `json:"Plan Rows"`
	Plans        []explainJSONNode `json:"Plans"`
}

// ParseExplainJSON extracts planner cost, estimated row count, and sequential-scan tables
// from PostgreSQL's EXPLAIN (FORMAT JSON) output.
func ParseExplainJSON(raw string) (*PlanMetrics, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("empty EXPLAIN JSON output")
	}
	var arr []explainJSONWrapper
	if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
		// Also accept single-object form {"Plan": ...}
		var single explainJSONWrapper
		if err2 := json.Unmarshal([]byte(trimmed), &single); err2 != nil {
			return nil, fmt.Errorf("parse EXPLAIN JSON: %w", err)
		}
		arr = []explainJSONWrapper{single}
	}
	if len(arr) == 0 {
		return nil, errors.New("EXPLAIN JSON returned empty plan list")
	}

	root := arr[0].Plan
	metrics := &PlanMetrics{
		TotalCost: root.TotalCost,
		PlanRows:  int64(root.PlanRows),
	}
	seenSeq := make(map[string]bool)
	var walk func(n explainJSONNode)
	walk = func(n explainJSONNode) {
		if n.TotalCost > metrics.TotalCost {
			metrics.TotalCost = n.TotalCost
		}
		if int64(n.PlanRows) > metrics.PlanRows {
			metrics.PlanRows = int64(n.PlanRows)
		}
		if strings.EqualFold(n.NodeType, "Seq Scan") && n.RelationName != "" {
			rel := strings.ToLower(n.RelationName)
			if !seenSeq[rel] {
				seenSeq[rel] = true
				metrics.SeqScanTables = append(metrics.SeqScanTables, rel)
			}
			if n.Schema != "" {
				qual := strings.ToLower(n.Schema + "." + n.RelationName)
				if !seenSeq[qual] {
					seenSeq[qual] = true
				}
			}
		}
		for _, child := range n.Plans {
			walk(child)
		}
	}
	walk(root)
	return metrics, nil
}

// EvaluateCostGuard checks extracted PlanMetrics against a profile's CostGuardPolicy.
func EvaluateCostGuard(pm *PlanMetrics, cfg policy.CostGuardPolicy) (blocked bool, rule, reason string) {
	if pm == nil || !cfg.Enabled {
		return false, "", ""
	}
	if cfg.MaxTotalCost > 0 && pm.TotalCost > cfg.MaxTotalCost {
		return true, "cost_guard_max_cost", fmt.Sprintf(
			"Query estimated planner cost (%.1f) exceeds profile max_total_cost (%.1f)",
			pm.TotalCost, cfg.MaxTotalCost,
		)
	}
	if cfg.MaxEstimatedRows > 0 && pm.PlanRows > cfg.MaxEstimatedRows {
		return true, "cost_guard_max_rows", fmt.Sprintf(
			"Query estimated row scan (%d rows) exceeds profile max_estimated_rows (%d)",
			pm.PlanRows, cfg.MaxEstimatedRows,
		)
	}
	if len(cfg.BlockSeqScanTables) > 0 && len(pm.SeqScanTables) > 0 {
		blockedSet := make(map[string]bool, len(cfg.BlockSeqScanTables))
		for _, t := range cfg.BlockSeqScanTables {
			lt := strings.ToLower(strings.TrimSpace(t))
			if lt != "" {
				blockedSet[lt] = true
				blockedSet[stripSchema(lt)] = true
			}
		}
		for _, seqTbl := range pm.SeqScanTables {
			if blockedSet[seqTbl] || blockedSet[stripSchema(seqTbl)] {
				return true, "cost_guard_seq_scan", fmt.Sprintf(
					"Unindexed Sequential Scan on protected table %q blocked by cost_guard",
					seqTbl,
				)
			}
		}
	}
	return false, "", ""
}

type planCacheEntry struct {
	key       string
	metrics   PlanMetrics
	expiresAt time.Time
}

// PlanCache is a thread-safe, bounded TTL LRU cache of EXPLAIN PlanMetrics keyed by
// (profile, policyVersion, AST fingerprint, applied RLS rules).
type PlanCache struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	ll         *list.List
	items      map[string]*list.Element
}

func NewPlanCache(maxEntries int, ttl time.Duration) *PlanCache {
	if maxEntries <= 0 {
		maxEntries = 2048
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &PlanCache{
		maxEntries: maxEntries,
		ttl:        ttl,
		ll:         list.New(),
		items:      make(map[string]*list.Element, 256),
	}
}

// CanonicalSQLKey collapses runs of unquoted whitespace while preserving quoted string/identifier
// literals and numeric constants verbatim (e.g. LIMIT 5 vs LIMIT 99999999 remain distinct cache keys).
func CanonicalSQLKey(sql string) string {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(trimmed))
	inSingle := false
	inDouble := false
	lastSpace := false
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		if inSingle {
			sb.WriteByte(ch)
			if ch == '\'' {
				if i+1 < len(trimmed) && trimmed[i+1] == '\'' {
					i++
					sb.WriteByte('\'')
				} else {
					inSingle = false
				}
			}
			continue
		}
		if inDouble {
			sb.WriteByte(ch)
			if ch == '"' {
				if i+1 < len(trimmed) && trimmed[i+1] == '"' {
					i++
					sb.WriteByte('"')
				} else {
					inDouble = false
				}
			}
			continue
		}
		if ch == '\'' {
			inSingle = true
			lastSpace = false
			sb.WriteByte(ch)
			continue
		}
		if ch == '"' {
			inDouble = true
			lastSpace = false
			sb.WriteByte(ch)
			continue
		}
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' {
			if !lastSpace {
				sb.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		lastSpace = false
		sb.WriteByte(ch)
	}
	return sb.String()
}

func BuildPlanCacheKey(profileName string, policyVer int64, sqlKey string, rlsRules []string) string {
	h := sha256.New()
	h.Write([]byte(profileName))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", policyVer)))
	h.Write([]byte{0})
	h.Write([]byte(sqlKey))
	h.Write([]byte{0})
	for _, r := range rlsRules {
		h.Write([]byte(r))
		h.Write([]byte{'|'})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func (c *PlanCache) Get(key string) (PlanMetrics, bool) {
	if c == nil || key == "" {
		return PlanMetrics{}, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return PlanMetrics{}, false
	}
	ent := el.Value.(*planCacheEntry)
	if now.After(ent.expiresAt) {
		c.ll.Remove(el)
		delete(c.items, key)
		return PlanMetrics{}, false
	}
	c.ll.MoveToFront(el)
	cp := ent.metrics
	if len(ent.metrics.SeqScanTables) > 0 {
		cp.SeqScanTables = append([]string(nil), ent.metrics.SeqScanTables...)
	}
	return cp, true
}

func (c *PlanCache) Put(key string, pm PlanMetrics) {
	if c == nil || key == "" {
		return
	}
	cp := pm
	if len(pm.SeqScanTables) > 0 {
		cp.SeqScanTables = append([]string(nil), pm.SeqScanTables...)
	}
	exp := time.Now().Add(c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		ent := el.Value.(*planCacheEntry)
		ent.metrics = cp
		ent.expiresAt = exp
		c.ll.MoveToFront(el)
		return
	}
	ent := &planCacheEntry{key: key, metrics: cp, expiresAt: exp}
	el := c.ll.PushFront(ent)
	c.items[key] = el
	for c.ll.Len() > c.maxEntries {
		back := c.ll.Back()
		if back == nil {
			break
		}
		old := back.Value.(*planCacheEntry)
		c.ll.Remove(back)
		delete(c.items, old.key)
	}
}
