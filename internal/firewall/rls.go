package firewall

import (
	"errors"
	"fmt"
	"strings"

	"github.com/duhanguler/pgveil/internal/policy"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// ErrMissingRLSClaim is returned when a row_filters predicate references {{jwt.<claim>}}
// and that claim is absent or empty in the verified session identity (strict fail-closed).
var ErrMissingRLSClaim = errors.New("missing required JWT claim for virtual RLS predicate")

// SessionContext carries authenticated PostgreSQL & verified JWT attributes available for
// Virtual Row-Level Security (RLS) predicate placeholders ({{db_user}}, {{jwt.tenant_id}}, etc.).
type SessionContext struct {
	DBUser          string
	Database        string
	ApplicationName string
	RoleProfile     string
	Claims          map[string]string
}

// RLSResult describes the outcome of AST-level Virtual RLS predicate injection.
type RLSResult struct {
	Rewritten    bool     `json:"rewritten"`
	SQL          string   `json:"sql"`
	RulesApplied []string `json:"rules_applied,omitempty"`
}

type compiledRowFilter struct {
	table   string // lowercased table or schema.table
	rawPred string // raw policy predicate template
}

// RewriteWithRLS inspects sql using PostgreSQL 17's C AST parser, injects any matching
// policy row_filters into SELECT / UPDATE / DELETE / MERGE / CTE / subquery / JOIN clauses,
// and emits canonical PostgreSQL SQL via pg_query.Deparse.
//
// Security invariant: Callers MUST run firewall.Evaluate() on the original SQL BEFORE calling
// RewriteWithRLS so unscoped writes (e.g. DELETE FROM orders) are caught before predicates are added.
func RewriteWithRLS(sql string, profile *policy.RoleProfile, sess SessionContext) (RLSResult, error) {
	if profile == nil || len(profile.Firewall.RowFilters) == 0 {
		return RLSResult{SQL: sql}, nil
	}
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || trimmed == ";" || strings.IndexByte(trimmed, 0) >= 0 {
		return RLSResult{SQL: sql}, nil
	}

	if sess.RoleProfile == "" {
		sess.RoleProfile = profile.Name
	}

	filters := make(map[string][]compiledRowFilter, len(profile.Firewall.RowFilters))
	for _, rf := range profile.Firewall.RowFilters {
		tbl := strings.ToLower(strings.TrimSpace(rf.Table))
		rawPred := strings.TrimSpace(rf.Predicate)
		if tbl == "" || rawPred == "" {
			continue
		}
		filters[tbl] = append(filters[tbl], compiledRowFilter{
			table:   tbl,
			rawPred: rawPred,
		})
	}
	if len(filters) == 0 {
		return RLSResult{SQL: sql}, nil
	}

	tree, err := pg_query.Parse(trimmed)
	if err != nil {
		return RLSResult{SQL: sql}, fmt.Errorf("parse SQL for virtual RLS: %w", err)
	}

	rw := &rlsRewriter{
		filters: filters,
		sess:    sess,
		applied: make(map[string]bool),
	}

	for _, raw := range tree.Stmts {
		if raw != nil && raw.Stmt != nil {
			if err := rw.rewriteNode(raw.Stmt, nil, 0); err != nil {
				return RLSResult{SQL: sql}, err
			}
		}
	}

	if !rw.rewritten {
		return RLSResult{SQL: sql}, nil
	}

	deparsed, err := pg_query.Deparse(tree)
	if err != nil {
		return RLSResult{SQL: sql}, fmt.Errorf("deparse virtual RLS AST: %w", err)
	}

	return RLSResult{
		Rewritten:    true,
		SQL:          deparsed,
		RulesApplied: rw.appliedOrder,
	}, nil
}

type rlsRewriter struct {
	filters      map[string][]compiledRowFilter
	sess         SessionContext
	rewritten    bool
	applied      map[string]bool
	appliedOrder []string
}

func (r *rlsRewriter) markApplied(rule string) {
	r.rewritten = true
	if !r.applied[rule] {
		r.applied[rule] = true
		r.appliedOrder = append(r.appliedOrder, rule)
	}
}

func (r *rlsRewriter) matchingFilters(rv *pg_query.RangeVar, cteNames map[string]bool) []compiledRowFilter {
	if rv == nil || rv.Relname == "" {
		return nil
	}
	bare := strings.ToLower(rv.Relname)
	// If unqualified and matches an in-scope CTE, do not re-inject onto the CTE output
	// (the underlying base table was already rewritten inside the CTE body).
	if rv.Schemaname == "" && cteNames[bare] {
		return nil
	}

	var matched []compiledRowFilter
	if rv.Schemaname != "" {
		full := strings.ToLower(rv.Schemaname + "." + rv.Relname)
		matched = append(matched, r.filters[full]...)
	}
	matched = append(matched, r.filters[bare]...)
	return matched
}

func (r *rlsRewriter) buildPredicateForRangeVar(rv *pg_query.RangeVar, cteNames map[string]bool) (*pg_query.Node, error) {
	matched := r.matchingFilters(rv, cteNames)
	if len(matched) == 0 {
		return nil, nil
	}

	// Determine table qualifier to prevent ambiguous column errors in JOINs.
	var qualifier []string
	if rv.Alias != nil && rv.Alias.Aliasname != "" {
		qualifier = []string{rv.Alias.Aliasname}
	} else if rv.Schemaname != "" {
		qualifier = []string{rv.Schemaname, rv.Relname}
	} else {
		qualifier = []string{rv.Relname}
	}

	var combined *pg_query.Node
	for _, f := range matched {
		expr, displayPred, err := compilePredicateAST(f.rawPred, r.sess)
		if err != nil {
			return nil, fmt.Errorf("compile row filter on %q: %w", f.table, err)
		}
		qualifyColumns(expr, qualifier, 0)
		combined = andExpr(combined, expr)
		r.markApplied(fmt.Sprintf("%s: %s", f.table, displayPred))
	}
	return combined, nil
}

func (r *rlsRewriter) rewriteWithClause(wc *pg_query.WithClause, parentCTEs map[string]bool, depth int) (map[string]bool, error) {
	scope := cloneStringBoolMap(parentCTEs)
	if wc == nil {
		return scope, nil
	}
	if wc.Recursive {
		for _, cteNode := range wc.Ctes {
			if cte := cteNode.GetCommonTableExpr(); cte != nil && cte.Ctename != "" {
				scope[strings.ToLower(cte.Ctename)] = true
			}
		}
	}
	for _, cteNode := range wc.Ctes {
		cte := cteNode.GetCommonTableExpr()
		if cte == nil {
			continue
		}
		if err := r.rewriteNode(cte.Ctequery, scope, depth+1); err != nil {
			return nil, err
		}
		if !wc.Recursive && cte.Ctename != "" {
			scope[strings.ToLower(cte.Ctename)] = true
		}
	}
	return scope, nil
}

func (r *rlsRewriter) rewriteNode(n *pg_query.Node, cteNames map[string]bool, depth int) error {
	if n == nil {
		return nil
	}
	if depth > maxASTDepth {
		return fmt.Errorf("AST depth exceeded during virtual RLS rewrite")
	}
	d := depth + 1

	switch x := n.Node.(type) {
	case *pg_query.Node_SelectStmt:
		return r.rewriteSelect(x.SelectStmt, cteNames, d)

	case *pg_query.Node_UpdateStmt:
		upd := x.UpdateStmt
		scope, err := r.rewriteWithClause(upd.WithClause, cteNames, d)
		if err != nil {
			return err
		}
		var added *pg_query.Node
		if pred, err := r.buildPredicateForRangeVar(upd.Relation, scope); err != nil {
			return err
		} else if pred != nil {
			added = andExpr(added, pred)
		}
		for i, fc := range upd.FromClause {
			pred, replaced, err := r.rewriteFromItem(fc, scope, d)
			if err != nil {
				return err
			}
			if replaced != nil {
				upd.FromClause[i] = replaced
			}
			added = andExpr(added, pred)
		}
		if err := r.rewriteExprSublinks(upd.WhereClause, scope, d); err != nil {
			return err
		}
		for _, t := range upd.TargetList {
			if err := r.rewriteExprSublinks(t, scope, d); err != nil {
				return err
			}
		}
		for _, ret := range upd.ReturningList {
			if err := r.rewriteExprSublinks(ret, scope, d); err != nil {
				return err
			}
		}
		if added != nil {
			upd.WhereClause = andExpr(upd.WhereClause, added)
		}

	case *pg_query.Node_DeleteStmt:
		del := x.DeleteStmt
		scope, err := r.rewriteWithClause(del.WithClause, cteNames, d)
		if err != nil {
			return err
		}
		var added *pg_query.Node
		if pred, err := r.buildPredicateForRangeVar(del.Relation, scope); err != nil {
			return err
		} else if pred != nil {
			added = andExpr(added, pred)
		}
		for i, u := range del.UsingClause {
			pred, replaced, err := r.rewriteFromItem(u, scope, d)
			if err != nil {
				return err
			}
			if replaced != nil {
				del.UsingClause[i] = replaced
			}
			added = andExpr(added, pred)
		}
		if err := r.rewriteExprSublinks(del.WhereClause, scope, d); err != nil {
			return err
		}
		for _, ret := range del.ReturningList {
			if err := r.rewriteExprSublinks(ret, scope, d); err != nil {
				return err
			}
		}
		if added != nil {
			del.WhereClause = andExpr(del.WhereClause, added)
		}

	case *pg_query.Node_InsertStmt:
		ins := x.InsertStmt
		scope, err := r.rewriteWithClause(ins.WithClause, cteNames, d)
		if err != nil {
			return err
		}
		if ins.SelectStmt != nil {
			if err := r.rewriteNode(ins.SelectStmt, scope, d); err != nil {
				return err
			}
		}
		for _, ret := range ins.ReturningList {
			if err := r.rewriteExprSublinks(ret, scope, d); err != nil {
				return err
			}
		}

	case *pg_query.Node_MergeStmt:
		ms := x.MergeStmt
		scope, err := r.rewriteWithClause(ms.WithClause, cteNames, d)
		if err != nil {
			return err
		}
		var added *pg_query.Node
		if pred, err := r.buildPredicateForRangeVar(ms.Relation, scope); err != nil {
			return err
		} else if pred != nil {
			added = andExpr(added, pred)
		}
		if ms.SourceRelation != nil {
			pred, replaced, err := r.rewriteFromItem(ms.SourceRelation, scope, d)
			if err != nil {
				return err
			}
			if replaced != nil {
				ms.SourceRelation = replaced
			}
			added = andExpr(added, pred)
		}
		if err := r.rewriteExprSublinks(ms.JoinCondition, scope, d); err != nil {
			return err
		}
		if added != nil {
			ms.JoinCondition = andExpr(ms.JoinCondition, added)
		}
		for _, mc := range ms.MergeWhenClauses {
			if mw := mc.GetMergeWhenClause(); mw != nil {
				if err := r.rewriteExprSublinks(mw.Condition, scope, d); err != nil {
					return err
				}
				for _, t := range mw.TargetList {
					if err := r.rewriteExprSublinks(t, scope, d); err != nil {
						return err
					}
				}
				for _, v := range mw.Values {
					if err := r.rewriteExprSublinks(v, scope, d); err != nil {
						return err
					}
				}
			}
		}

	case *pg_query.Node_ExplainStmt:
		return r.rewriteNode(x.ExplainStmt.Query, cteNames, d)

	case *pg_query.Node_PrepareStmt:
		return r.rewriteNode(x.PrepareStmt.Query, cteNames, d)

	case *pg_query.Node_DeclareCursorStmt:
		return r.rewriteNode(x.DeclareCursorStmt.Query, cteNames, d)

	case *pg_query.Node_CopyStmt:
		if x.CopyStmt.Query != nil {
			return r.rewriteNode(x.CopyStmt.Query, cteNames, d)
		}
	}
	return nil
}

func (r *rlsRewriter) rewriteSelect(sel *pg_query.SelectStmt, cteNames map[string]bool, depth int) error {
	if sel == nil {
		return nil
	}
	scope, err := r.rewriteWithClause(sel.WithClause, cteNames, depth)
	if err != nil {
		return err
	}

	// Set operations (UNION / INTERSECT / EXCEPT)
	if sel.Larg != nil || sel.Rarg != nil {
		if sel.Larg != nil {
			if err := r.rewriteSelect(sel.Larg, scope, depth+1); err != nil {
				return err
			}
		}
		if sel.Rarg != nil {
			if err := r.rewriteSelect(sel.Rarg, scope, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	var added *pg_query.Node
	for i, fc := range sel.FromClause {
		pred, replaced, err := r.rewriteFromItem(fc, scope, depth+1)
		if err != nil {
			return err
		}
		if replaced != nil {
			sel.FromClause[i] = replaced
		}
		added = andExpr(added, pred)
	}

	// Walk subqueries inside SELECT expressions, WHERE, HAVING, GROUP, ORDER, LIMIT
	for _, tl := range sel.TargetList {
		if err := r.rewriteExprSublinks(tl, scope, depth+1); err != nil {
			return err
		}
	}
	if err := r.rewriteExprSublinks(sel.WhereClause, scope, depth+1); err != nil {
		return err
	}
	if err := r.rewriteExprSublinks(sel.HavingClause, scope, depth+1); err != nil {
		return err
	}
	for _, g := range sel.GroupClause {
		if err := r.rewriteExprSublinks(g, scope, depth+1); err != nil {
			return err
		}
	}
	for _, sc := range sel.SortClause {
		if err := r.rewriteExprSublinks(sc, scope, depth+1); err != nil {
			return err
		}
	}
	if err := r.rewriteExprSublinks(sel.LimitCount, scope, depth+1); err != nil {
		return err
	}
	if err := r.rewriteExprSublinks(sel.LimitOffset, scope, depth+1); err != nil {
		return err
	}

	if added != nil {
		sel.WhereClause = andExpr(sel.WhereClause, added)
	}
	return nil
}

// rewriteFromItem processes a FROM / JOIN element, returning:
//   - pred: predicates that must be AND-ed into the enclosing WHERE (or JOIN ON) clause
//   - replaced: non-nil if the FROM item was wrapped in a filtered subquery (e.g. FULL OUTER JOIN / USING)
func (r *rlsRewriter) rewriteFromItem(n *pg_query.Node, cteNames map[string]bool, depth int) (pred *pg_query.Node, replaced *pg_query.Node, err error) {
	if n == nil {
		return nil, nil, nil
	}
	if depth > maxASTDepth {
		return nil, nil, fmt.Errorf("AST depth exceeded in FROM clause")
	}

	switch x := n.Node.(type) {
	case *pg_query.Node_RangeVar:
		p, err := r.buildPredicateForRangeVar(x.RangeVar, cteNames)
		return p, nil, err

	case *pg_query.Node_RangeSubselect:
		if err := r.rewriteNode(x.RangeSubselect.Subquery, cteNames, depth+1); err != nil {
			return nil, nil, err
		}
		return nil, nil, nil

	case *pg_query.Node_JoinExpr:
		je := x.JoinExpr
		if err := r.rewriteExprSublinks(je.Quals, cteNames, depth+1); err != nil {
			return nil, nil, err
		}

		// FULL OUTER JOIN or NATURAL / USING joins cannot safely receive outer-side predicates in ON
		// without changing semantics or producing invalid SQL; wrap filtered RangeVars as subqueries.
		if je.Jointype == pg_query.JoinType_JOIN_FULL {
			if repL, err := r.wrapIfFiltered(je.Larg, cteNames, depth+1); err != nil {
				return nil, nil, err
			} else if repL != nil {
				je.Larg = repL
			}
			if repR, err := r.wrapIfFiltered(je.Rarg, cteNames, depth+1); err != nil {
				return nil, nil, err
			} else if repR != nil {
				je.Rarg = repR
			}
			return nil, nil, nil
		}

		hasUsingOrNatural := je.IsNatural || len(je.UsingClause) > 0

		switch je.Jointype {
		case pg_query.JoinType_JOIN_LEFT:
			// Left side filters safely go to enclosing WHERE; right side filters belong in ON (or subquery if USING/NATURAL)
			lPred, repL, err := r.rewriteFromItem(je.Larg, cteNames, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if repL != nil {
				je.Larg = repL
			}
			if hasUsingOrNatural {
				if repR, err := r.wrapIfFiltered(je.Rarg, cteNames, depth+1); err != nil {
					return nil, nil, err
				} else if repR != nil {
					je.Rarg = repR
				}
			} else {
				rPred, repR, err := r.rewriteFromItem(je.Rarg, cteNames, depth+1)
				if err != nil {
					return nil, nil, err
				}
				if repR != nil {
					je.Rarg = repR
				}
				if rPred != nil {
					je.Quals = andExpr(je.Quals, rPred)
				}
			}
			return lPred, nil, nil

		case pg_query.JoinType_JOIN_RIGHT:
			// Right side filters safely go to enclosing WHERE; left side filters belong in ON (or subquery if USING/NATURAL)
			rPred, repR, err := r.rewriteFromItem(je.Rarg, cteNames, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if repR != nil {
				je.Rarg = repR
			}
			if hasUsingOrNatural {
				if repL, err := r.wrapIfFiltered(je.Larg, cteNames, depth+1); err != nil {
					return nil, nil, err
				} else if repL != nil {
					je.Larg = repL
				}
			} else {
				lPred, repL, err := r.rewriteFromItem(je.Larg, cteNames, depth+1)
				if err != nil {
					return nil, nil, err
				}
				if repL != nil {
					je.Larg = repL
				}
				if lPred != nil {
					je.Quals = andExpr(je.Quals, lPred)
				}
			}
			return rPred, nil, nil

		default: // INNER JOIN / CROSS JOIN
			lPred, repL, err := r.rewriteFromItem(je.Larg, cteNames, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if repL != nil {
				je.Larg = repL
			}
			rPred, repR, err := r.rewriteFromItem(je.Rarg, cteNames, depth+1)
			if err != nil {
				return nil, nil, err
			}
			if repR != nil {
				je.Rarg = repR
			}
			return andExpr(lPred, rPred), nil, nil
		}
	}
	return nil, nil, nil
}

// wrapIfFiltered wraps a filtered RangeVar in `(SELECT * FROM tbl WHERE <pred>) AS <alias>`
// so FULL OUTER JOIN and NATURAL/USING joins never leak unauthorized rows or break SQL grammar.
func (r *rlsRewriter) wrapIfFiltered(n *pg_query.Node, cteNames map[string]bool, depth int) (*pg_query.Node, error) {
	if n == nil {
		return nil, nil
	}
	if rv := n.GetRangeVar(); rv != nil {
		matched := r.matchingFilters(rv, cteNames)
		if len(matched) == 0 {
			return nil, nil
		}
		// Build inner clean RangeVar without outer alias, preserve alias on outer RangeSubselect
		aliasName := rv.Relname
		var colAliases []*pg_query.Node
		if rv.Alias != nil {
			if rv.Alias.Aliasname != "" {
				aliasName = rv.Alias.Aliasname
			}
			colAliases = rv.Alias.Colnames
		}
		innerRV := &pg_query.RangeVar{
			Schemaname: rv.Schemaname,
			Relname:    rv.Relname,
			Inh:        rv.Inh,
		}
		pred, err := r.buildPredicateForRangeVar(innerRV, cteNames)
		if err != nil || pred == nil {
			return nil, err
		}
		subSel := &pg_query.SelectStmt{
			TargetList: []*pg_query.Node{
				{
					Node: &pg_query.Node_ResTarget{
						ResTarget: &pg_query.ResTarget{
							Val: &pg_query.Node{
								Node: &pg_query.Node_ColumnRef{
									ColumnRef: &pg_query.ColumnRef{
										Fields: []*pg_query.Node{
											{Node: &pg_query.Node_AStar{AStar: &pg_query.A_Star{}}},
										},
									},
								},
							},
						},
					},
				},
			},
			FromClause: []*pg_query.Node{
				{Node: &pg_query.Node_RangeVar{RangeVar: innerRV}},
			},
			WhereClause: pred,
		}
		return &pg_query.Node{
			Node: &pg_query.Node_RangeSubselect{
				RangeSubselect: &pg_query.RangeSubselect{
					Subquery: &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: subSel}},
					Alias: &pg_query.Alias{
						Aliasname: aliasName,
						Colnames:  colAliases,
					},
				},
			},
		}, nil
	}

	// Recurse if it's a nested JoinExpr or RangeSubselect
	pred, rep, err := r.rewriteFromItem(n, cteNames, depth+1)
	if err != nil {
		return nil, err
	}
	if pred != nil && n.GetJoinExpr() != nil {
		n.GetJoinExpr().Quals = andExpr(n.GetJoinExpr().Quals, pred)
	}
	return rep, nil
}

func (r *rlsRewriter) rewriteExprSublinks(n *pg_query.Node, cteNames map[string]bool, depth int) error {
	if n == nil || depth > maxASTDepth {
		return nil
	}
	d := depth + 1

	switch x := n.Node.(type) {
	case *pg_query.Node_SubLink:
		if err := r.rewriteExprSublinks(x.SubLink.Testexpr, cteNames, d); err != nil {
			return err
		}
		return r.rewriteNode(x.SubLink.Subselect, cteNames, d)

	case *pg_query.Node_ResTarget:
		return r.rewriteExprSublinks(x.ResTarget.Val, cteNames, d)

	case *pg_query.Node_BoolExpr:
		for _, arg := range x.BoolExpr.Args {
			if err := r.rewriteExprSublinks(arg, cteNames, d); err != nil {
				return err
			}
		}

	case *pg_query.Node_AExpr:
		if err := r.rewriteExprSublinks(x.AExpr.Lexpr, cteNames, d); err != nil {
			return err
		}
		return r.rewriteExprSublinks(x.AExpr.Rexpr, cteNames, d)

	case *pg_query.Node_FuncCall:
		for _, arg := range x.FuncCall.Args {
			if err := r.rewriteExprSublinks(arg, cteNames, d); err != nil {
				return err
			}
		}
		return r.rewriteExprSublinks(x.FuncCall.AggFilter, cteNames, d)

	case *pg_query.Node_CaseExpr:
		if err := r.rewriteExprSublinks(x.CaseExpr.Arg, cteNames, d); err != nil {
			return err
		}
		for _, w := range x.CaseExpr.Args {
			if err := r.rewriteExprSublinks(w, cteNames, d); err != nil {
				return err
			}
		}
		return r.rewriteExprSublinks(x.CaseExpr.Defresult, cteNames, d)

	case *pg_query.Node_CaseWhen:
		if err := r.rewriteExprSublinks(x.CaseWhen.Expr, cteNames, d); err != nil {
			return err
		}
		return r.rewriteExprSublinks(x.CaseWhen.Result, cteNames, d)

	case *pg_query.Node_CoalesceExpr:
		for _, a := range x.CoalesceExpr.Args {
			if err := r.rewriteExprSublinks(a, cteNames, d); err != nil {
				return err
			}
		}

	case *pg_query.Node_TypeCast:
		return r.rewriteExprSublinks(x.TypeCast.Arg, cteNames, d)

	case *pg_query.Node_NullTest:
		return r.rewriteExprSublinks(x.NullTest.Arg, cteNames, d)

	case *pg_query.Node_BooleanTest:
		return r.rewriteExprSublinks(x.BooleanTest.Arg, cteNames, d)

	case *pg_query.Node_SortBy:
		return r.rewriteExprSublinks(x.SortBy.Node, cteNames, d)

	case *pg_query.Node_List:
		for _, it := range x.List.Items {
			if err := r.rewriteExprSublinks(it, cteNames, d); err != nil {
				return err
			}
		}

	case *pg_query.Node_RowExpr:
		for _, a := range x.RowExpr.Args {
			if err := r.rewriteExprSublinks(a, cteNames, d); err != nil {
				return err
			}
		}
	}
	return nil
}

// compilePredicateAST parses a row_filters predicate using sentinel placeholders (__pgveil_ph_N__)
// and injects untrusted session / JWT claim values directly into parsed pg_query.A_Const AST nodes.
// Because untrusted claim values never touch the SQL lexer prior to pg_query.Parse, second-order
// SQL injection (via dollar-quotes, C-escapes, comments, or quote breakout) is structurally impossible.
type sentinelBinding struct {
	token string
	value string
}

func compilePredicateAST(rawPred string, sess SessionContext) (*pg_query.Node, string, error) {
	var bindings []sentinelBinding
	var templated strings.Builder
	templated.Grow(len(rawPred) + 32)

	inQuote := false
	for i := 0; i < len(rawPred); {
		if rawPred[i] == '\'' {
			templated.WriteByte('\'')
			if inQuote && i+1 < len(rawPred) && rawPred[i+1] == '\'' {
				templated.WriteByte('\'')
				i += 2
				continue
			}
			inQuote = !inQuote
			i++
			continue
		}
		if strings.HasPrefix(rawPred[i:], "{{") {
			if end := strings.Index(rawPred[i:], "}}"); end > 2 {
				key := strings.TrimSpace(rawPred[i+2 : i+end])
				val, err := resolvePlaceholderValue(key, sess)
				if err != nil {
					return nil, "", err
				}
				tok := fmt.Sprintf("__pgveil_ph_%d__", len(bindings))
				bindings = append(bindings, sentinelBinding{
					token: tok,
					value: strings.ReplaceAll(val, "\x00", ""),
				})
				if inQuote {
					templated.WriteString(tok)
				} else {
					templated.WriteByte('\'')
					templated.WriteString(tok)
					templated.WriteByte('\'')
				}
				i += end + 2
				continue
			}
		}
		templated.WriteByte(rawPred[i])
		i++
	}

	tree, err := pg_query.Parse("SELECT 1 WHERE " + templated.String())
	if err != nil {
		return nil, "", err
	}
	if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		return nil, "", fmt.Errorf("predicate must parse to a single expression")
	}
	sel := tree.Stmts[0].Stmt.GetSelectStmt()
	if sel == nil || sel.WhereClause == nil {
		return nil, "", fmt.Errorf("predicate missing WHERE expression")
	}

	if len(bindings) > 0 {
		pairs := make([]string, 0, len(bindings)*2)
		for _, b := range bindings {
			pairs = append(pairs, b.token, b.value)
		}
		replacer := strings.NewReplacer(pairs...)
		injectSentinelASTValues(sel.WhereClause, replacer, 0)
	}

	displayPred := rawPred
	if dep, derr := pg_query.Deparse(tree); derr == nil {
		const pfx = "SELECT 1 WHERE "
		if strings.HasPrefix(dep, pfx) {
			displayPred = strings.TrimPrefix(dep, pfx)
		} else {
			displayPred = dep
		}
	}
	return sel.WhereClause, displayPred, nil
}

func resolvePlaceholderValue(key string, sess SessionContext) (string, error) {
	switch key {
	case "db_user":
		return sess.DBUser, nil
	case "database":
		return sess.Database, nil
	case "application_name":
		return sess.ApplicationName, nil
	case "profile":
		return sess.RoleProfile, nil
	default:
		if strings.HasPrefix(key, "jwt.") {
			claim := strings.TrimPrefix(key, "jwt.")
			if claim == "" || sess.Claims == nil {
				return "", fmt.Errorf("%w: {{%s}}", ErrMissingRLSClaim, key)
			}
			val, ok := sess.Claims[claim]
			if !ok || strings.TrimSpace(val) == "" {
				return "", fmt.Errorf("%w: {{%s}}", ErrMissingRLSClaim, key)
			}
			return val, nil
		}
		return "", fmt.Errorf("unsupported RLS placeholder {{%s}}", key)
	}
}

func injectSentinelASTValues(n *pg_query.Node, replacer *strings.Replacer, depth int) {
	if n == nil || depth > 64 {
		return
	}
	d := depth + 1
	switch x := n.Node.(type) {
	case *pg_query.Node_AConst:
		if sv := x.AConst.GetSval(); sv != nil {
			sv.Sval = replacer.Replace(sv.Sval)
		}
	case *pg_query.Node_BoolExpr:
		for _, a := range x.BoolExpr.Args {
			injectSentinelASTValues(a, replacer, d)
		}
	case *pg_query.Node_AExpr:
		injectSentinelASTValues(x.AExpr.Lexpr, replacer, d)
		injectSentinelASTValues(x.AExpr.Rexpr, replacer, d)
	case *pg_query.Node_FuncCall:
		for _, a := range x.FuncCall.Args {
			injectSentinelASTValues(a, replacer, d)
		}
		injectSentinelASTValues(x.FuncCall.AggFilter, replacer, d)
	case *pg_query.Node_TypeCast:
		injectSentinelASTValues(x.TypeCast.Arg, replacer, d)
	case *pg_query.Node_NullTest:
		injectSentinelASTValues(x.NullTest.Arg, replacer, d)
	case *pg_query.Node_BooleanTest:
		injectSentinelASTValues(x.BooleanTest.Arg, replacer, d)
	case *pg_query.Node_CoalesceExpr:
		for _, a := range x.CoalesceExpr.Args {
			injectSentinelASTValues(a, replacer, d)
		}
	case *pg_query.Node_MinMaxExpr:
		for _, a := range x.MinMaxExpr.Args {
			injectSentinelASTValues(a, replacer, d)
		}
	case *pg_query.Node_CaseExpr:
		injectSentinelASTValues(x.CaseExpr.Arg, replacer, d)
		for _, w := range x.CaseExpr.Args {
			injectSentinelASTValues(w, replacer, d)
		}
		injectSentinelASTValues(x.CaseExpr.Defresult, replacer, d)
	case *pg_query.Node_CaseWhen:
		injectSentinelASTValues(x.CaseWhen.Expr, replacer, d)
		injectSentinelASTValues(x.CaseWhen.Result, replacer, d)
	case *pg_query.Node_List:
		for _, it := range x.List.Items {
			injectSentinelASTValues(it, replacer, d)
		}
	case *pg_query.Node_AArrayExpr:
		for _, el := range x.AArrayExpr.Elements {
			injectSentinelASTValues(el, replacer, d)
		}
	case *pg_query.Node_RowExpr:
		for _, el := range x.RowExpr.Args {
			injectSentinelASTValues(el, replacer, d)
		}
	}
}

// qualifyColumns prepends table/alias qualifiers to every unqualified ColumnRef inside a row filter
// expression so multi-table JOINs never fail with "column reference is ambiguous".
func qualifyColumns(n *pg_query.Node, qualifier []string, depth int) {
	if n == nil || len(qualifier) == 0 || depth > 64 {
		return
	}
	d := depth + 1
	switch x := n.Node.(type) {
	case *pg_query.Node_ColumnRef:
		cr := x.ColumnRef
		if len(cr.Fields) == 1 && cr.Fields[0].GetString_() != nil {
			prefix := make([]*pg_query.Node, 0, len(qualifier)+1)
			for _, q := range qualifier {
				prefix = append(prefix, &pg_query.Node{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: q}}})
			}
			prefix = append(prefix, cr.Fields[0])
			cr.Fields = prefix
		}
	case *pg_query.Node_BoolExpr:
		for _, a := range x.BoolExpr.Args {
			qualifyColumns(a, qualifier, d)
		}
	case *pg_query.Node_AExpr:
		qualifyColumns(x.AExpr.Lexpr, qualifier, d)
		qualifyColumns(x.AExpr.Rexpr, qualifier, d)
	case *pg_query.Node_FuncCall:
		for _, a := range x.FuncCall.Args {
			qualifyColumns(a, qualifier, d)
		}
	case *pg_query.Node_TypeCast:
		qualifyColumns(x.TypeCast.Arg, qualifier, d)
	case *pg_query.Node_NullTest:
		qualifyColumns(x.NullTest.Arg, qualifier, d)
	case *pg_query.Node_BooleanTest:
		qualifyColumns(x.BooleanTest.Arg, qualifier, d)
	case *pg_query.Node_CoalesceExpr:
		for _, a := range x.CoalesceExpr.Args {
			qualifyColumns(a, qualifier, d)
		}
	case *pg_query.Node_MinMaxExpr:
		for _, a := range x.MinMaxExpr.Args {
			qualifyColumns(a, qualifier, d)
		}
	case *pg_query.Node_CaseExpr:
		qualifyColumns(x.CaseExpr.Arg, qualifier, d)
		for _, w := range x.CaseExpr.Args {
			if cw := w.GetCaseWhen(); cw != nil {
				qualifyColumns(cw.Expr, qualifier, d)
				qualifyColumns(cw.Result, qualifier, d)
			}
		}
		qualifyColumns(x.CaseExpr.Defresult, qualifier, d)
	case *pg_query.Node_List:
		for _, it := range x.List.Items {
			qualifyColumns(it, qualifier, d)
		}
	case *pg_query.Node_AArrayExpr:
		for _, el := range x.AArrayExpr.Elements {
			qualifyColumns(el, qualifier, d)
		}
	case *pg_query.Node_RowExpr:
		for _, el := range x.RowExpr.Args {
			qualifyColumns(el, qualifier, d)
		}
	}
}

func andExpr(left, right *pg_query.Node) *pg_query.Node {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return &pg_query.Node{
		Node: &pg_query.Node_BoolExpr{
			BoolExpr: &pg_query.BoolExpr{
				Boolop: pg_query.BoolExprType_AND_EXPR,
				Args:   []*pg_query.Node{left, right},
			},
		},
	}
}

func cloneStringBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}
