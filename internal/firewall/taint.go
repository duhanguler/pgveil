package firewall

import (
	"fmt"
	"strings"

	"github.com/duhanguler/pgveil/internal/policy"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// piiExfilFuncs are string/encoding/hashing/aggregation/JSON/XML functions that could slice,
// encode, serialize, or transform a masked column to evade wire-level masking or leak raw bits.
var piiExfilFuncs = map[string]bool{
	"substring":           true,
	"substr":              true,
	"left":                true,
	"right":               true,
	"ascii":               true,
	"chr":                 true,
	"length":              true,
	"char_length":         true,
	"character_length":    true,
	"octet_length":        true,
	"bit_length":          true,
	"md5":                 true,
	"sha256":              true,
	"sha512":              true,
	"digest":              true,
	"encode":              true,
	"decode":              true,
	"convert_to":          true,
	"convert":             true,
	"to_hex":              true,
	"split_part":          true,
	"string_to_array":     true,
	"regexp_split_to_array": true,
	"regexp_split_to_table": true,
	"regexp_match":        true,
	"regexp_matches":      true,
	"regexp_replace":      true,
	"regexp_substr":       true,
	"regexp_count":        true,
	"regexp_instr":        true,
	"starts_with":         true,
	"reverse":             true,
	"concat":              true,
	"concat_ws":           true,
	"format":              true,
	"overlay":             true,
	"replace":             true,
	"position":            true,
	"strpos":              true,
	"translate":           true,
	"btrim":               true,
	"ltrim":               true,
	"rtrim":               true,
	"trim":                true,
	"upper":               true,
	"lower":               true,
	"initcap":             true,
	"lpad":                true,
	"rpad":                true,
	"repeat":              true,
	"quote_literal":       true,
	"quote_nullable":      true,
	"string_agg":          true,
	"array_agg":           true,
	"json_agg":            true,
	"jsonb_agg":           true,
	"to_json":             true,
	"to_jsonb":            true,
	"row_to_json":         true,
	"json_build_object":   true,
	"jsonb_build_object":  true,
	"json_build_array":    true,
	"jsonb_build_array":   true,
	"min":                 true,
	"max":                 true,
}

var riskyCastTypes = map[string]bool{
	"bytea":   true,
	"int2":    true,
	"int4":    true,
	"int8":    true,
	"integer": true,
	"bigint":  true,
	"numeric": true,
	"decimal": true,
	"json":    true,
	"jsonb":   true,
	"bit":     true,
	"varbit":  true,
	"xml":     true,
}

func isRiskyCast(tc *pg_query.TypeCast) bool {
	if tc == nil || tc.TypeName == nil {
		return false
	}
	for _, n := range tc.TypeName.Names {
		if s := n.GetString_(); s != nil && riskyCastTypes[strings.ToLower(s.Sval)] {
			return true
		}
	}
	return false
}

func resolveProtectedColumns(profile *policy.RoleProfile) map[string]bool {
	set := make(map[string]bool)
	if profile == nil {
		return set
	}
	if len(profile.Firewall.ProtectedColumns) > 0 {
		for _, c := range profile.Firewall.ProtectedColumns {
			if s := strings.ToLower(strings.TrimSpace(c)); s != "" {
				set[s] = true
			}
		}
		return set
	}
	for _, r := range profile.Masking.ColumnRules {
		if s := strings.ToLower(strings.TrimSpace(r.Column)); s != "" {
			set[s] = true
		}
	}
	return set
}

// collectRelationNames gathers table names and table aliases declared in a SELECT's FROM/JOIN/WITH
// clauses so whole-row record exfiltration (e.g. `SELECT c::text FROM customers c` or
// `SELECT row_to_json(customers) FROM customers`) can be detected and blocked.
func collectRelationNames(fromClause []*pg_query.Node) map[string]bool {
	rels := make(map[string]bool)
	var visit func(n *pg_query.Node)
	visit = func(n *pg_query.Node) {
		if n == nil {
			return
		}
		switch inner := n.Node.(type) {
		case *pg_query.Node_RangeVar:
			if inner.RangeVar.Relname != "" {
				rels[strings.ToLower(inner.RangeVar.Relname)] = true
			}
			if inner.RangeVar.Alias != nil && inner.RangeVar.Alias.Aliasname != "" {
				rels[strings.ToLower(inner.RangeVar.Alias.Aliasname)] = true
			}
		case *pg_query.Node_RangeSubselect:
			if inner.RangeSubselect.Alias != nil && inner.RangeSubselect.Alias.Aliasname != "" {
				rels[strings.ToLower(inner.RangeSubselect.Alias.Aliasname)] = true
			}
		case *pg_query.Node_JoinExpr:
			visit(inner.JoinExpr.Larg)
			visit(inner.JoinExpr.Rarg)
		}
	}
	for _, fc := range fromClause {
		visit(fc)
	}
	return rels
}

// propagateTaintedAliases computes a fixed-point set of all column aliases across CTEs and
// subqueries that transitively derive from any protected PII column.
// Example: `WITH a AS (SELECT tckn AS p1 FROM customers), b AS (SELECT p1 AS p2 FROM a) SELECT * FROM b WHERE p2 LIKE '1%'`
// marks `p1` and `p2` as tainted so the outer WHERE probe is caught!
func propagateTaintedAliases(tree *pg_query.ParseResult, baseProtected map[string]bool) map[string]bool {
	tainted := make(map[string]bool, len(baseProtected)+8)
	for k, v := range baseProtected {
		if v {
			tainted[k] = true
		}
	}

	type aliasEdge struct {
		alias string
		cols  []string
	}
	var edges []aliasEdge

	var scanSelect func(n *pg_query.Node, depth int)
	scanSelect = func(n *pg_query.Node, depth int) {
		if n == nil || depth > 48 {
			return
		}
		d := depth + 1
		switch inner := n.Node.(type) {
		case *pg_query.Node_SelectStmt:
			s := inner.SelectStmt
			if s.WithClause != nil {
				for _, cte := range s.WithClause.Ctes {
					if cn := cte.GetCommonTableExpr(); cn != nil {
						// Also map explicit CTE column list: `WITH c(x, y) AS (SELECT id, tckn FROM customers)`
						scanSelect(cn.Ctequery, d)
						if len(cn.Aliascolnames) > 0 && cn.Ctequery != nil {
							if sel := cn.Ctequery.GetSelectStmt(); sel != nil {
								for idx, ac := range cn.Aliascolnames {
									if sNode := ac.GetString_(); sNode != nil && idx < len(sel.TargetList) {
										var src []string
										collectExprColRefs(sel.TargetList[idx], &src, 0)
										if len(src) > 0 {
											edges = append(edges, aliasEdge{alias: strings.ToLower(sNode.Sval), cols: src})
										}
									}
								}
							}
						}
					}
				}
			}
			for _, tl := range s.TargetList {
				rt := tl.GetResTarget()
				if rt == nil {
					continue
				}
				if rt.Name != "" {
					var src []string
					collectExprColRefs(rt.Val, &src, 0)
					if len(src) > 0 {
						edges = append(edges, aliasEdge{alias: strings.ToLower(rt.Name), cols: src})
					}
				}
				scanSelect(rt.Val, d)
			}
			for _, fc := range s.FromClause {
				scanSelect(fc, d)
			}
			if s.Larg != nil {
				scanSelect(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Larg}}, d)
			}
			if s.Rarg != nil {
				scanSelect(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Rarg}}, d)
			}
		case *pg_query.Node_RangeSubselect:
			scanSelect(inner.RangeSubselect.Subquery, d)
			// Map subquery alias column names: `(SELECT id, tckn FROM customers) AS sub(a, b)`
			if inner.RangeSubselect.Alias != nil && len(inner.RangeSubselect.Alias.Colnames) > 0 && inner.RangeSubselect.Subquery != nil {
				if sel := inner.RangeSubselect.Subquery.GetSelectStmt(); sel != nil {
					for idx, cn := range inner.RangeSubselect.Alias.Colnames {
						if sNode := cn.GetString_(); sNode != nil && idx < len(sel.TargetList) {
							var src []string
							collectExprColRefs(sel.TargetList[idx], &src, 0)
							if len(src) > 0 {
								edges = append(edges, aliasEdge{alias: strings.ToLower(sNode.Sval), cols: src})
							}
						}
					}
				}
			}
		case *pg_query.Node_JoinExpr:
			scanSelect(inner.JoinExpr.Larg, d)
			scanSelect(inner.JoinExpr.Rarg, d)
		case *pg_query.Node_SubLink:
			scanSelect(inner.SubLink.Subselect, d)
		case *pg_query.Node_ExplainStmt:
			scanSelect(inner.ExplainStmt.Query, d)
		case *pg_query.Node_PrepareStmt:
			scanSelect(inner.PrepareStmt.Query, d)
		case *pg_query.Node_DeclareCursorStmt:
			scanSelect(inner.DeclareCursorStmt.Query, d)
		case *pg_query.Node_InsertStmt:
			scanSelect(inner.InsertStmt.SelectStmt, d)
		case *pg_query.Node_UpdateStmt:
			if inner.UpdateStmt.WithClause != nil {
				for _, cte := range inner.UpdateStmt.WithClause.Ctes {
					if cn := cte.GetCommonTableExpr(); cn != nil {
						scanSelect(cn.Ctequery, d)
					}
				}
			}
		case *pg_query.Node_DeleteStmt:
			if inner.DeleteStmt.WithClause != nil {
				for _, cte := range inner.DeleteStmt.WithClause.Ctes {
					if cn := cte.GetCommonTableExpr(); cn != nil {
						scanSelect(cn.Ctequery, d)
					}
				}
			}
		}
	}

	for _, raw := range tree.Stmts {
		if raw != nil && raw.Stmt != nil {
			scanSelect(raw.Stmt, 0)
		}
	}

	// Fixed-point taint propagation across multi-hop CTE / subquery aliases
	for changed := true; changed; {
		changed = false
		for _, e := range edges {
			if tainted[e.alias] {
				continue
			}
			for _, src := range e.cols {
				if tainted[src] {
					tainted[e.alias] = true
					changed = true
					break
				}
			}
		}
	}
	return tainted
}

// detectPIIInference traverses the PostgreSQL 17 AST with transitive alias taint tracking
// to catch side-channel oracle probes and whole-row record exfiltration.
func detectPIIInference(tree *pg_query.ParseResult, baseProtected map[string]bool) (col string, rule string, via string) {
	protected := propagateTaintedAliases(tree, baseProtected)

	var walkStmt func(n *pg_query.Node, depth int) (string, string, string)
	var findColInExpr func(n *pg_query.Node, depth int) string

	findColInExpr = func(n *pg_query.Node, depth int) string {
		if n == nil || depth > maxASTDepth {
			return ""
		}
		d := depth + 1
		switch inner := n.Node.(type) {
		case *pg_query.Node_ColumnRef:
			if len(inner.ColumnRef.Fields) > 0 {
				last := inner.ColumnRef.Fields[len(inner.ColumnRef.Fields)-1]
				if s := last.GetString_(); s != nil {
					name := strings.ToLower(s.Sval)
					if protected[name] {
						return name
					}
				}
			}
		case *pg_query.Node_AExpr:
			if c := findColInExpr(inner.AExpr.Lexpr, d); c != "" {
				return c
			}
			return findColInExpr(inner.AExpr.Rexpr, d)
		case *pg_query.Node_BoolExpr:
			for _, a := range inner.BoolExpr.Args {
				if c := findColInExpr(a, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_FuncCall:
			for _, a := range inner.FuncCall.Args {
				if c := findColInExpr(a, d); c != "" {
					return c
				}
			}
			if c := findColInExpr(inner.FuncCall.AggFilter, d); c != "" {
				return c
			}
			if inner.FuncCall.Over != nil {
				for _, p := range inner.FuncCall.Over.PartitionClause {
					if c := findColInExpr(p, d); c != "" {
						return c
					}
				}
				for _, o := range inner.FuncCall.Over.OrderClause {
					if c := findColInExpr(o, d); c != "" {
						return c
					}
				}
			}
		case *pg_query.Node_WindowDef:
			for _, p := range inner.WindowDef.PartitionClause {
				if c := findColInExpr(p, d); c != "" {
					return c
				}
			}
			for _, o := range inner.WindowDef.OrderClause {
				if c := findColInExpr(o, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_TypeCast:
			return findColInExpr(inner.TypeCast.Arg, d)
		case *pg_query.Node_NullTest:
			return findColInExpr(inner.NullTest.Arg, d)
		case *pg_query.Node_BooleanTest:
			return findColInExpr(inner.BooleanTest.Arg, d)
		case *pg_query.Node_NamedArgExpr:
			return findColInExpr(inner.NamedArgExpr.Arg, d)
		case *pg_query.Node_CaseExpr:
			if c := findColInExpr(inner.CaseExpr.Arg, d); c != "" {
				return c
			}
			for _, w := range inner.CaseExpr.Args {
				if c := findColInExpr(w, d); c != "" {
					return c
				}
			}
			return findColInExpr(inner.CaseExpr.Defresult, d)
		case *pg_query.Node_CaseWhen:
			if c := findColInExpr(inner.CaseWhen.Expr, d); c != "" {
				return c
			}
			return findColInExpr(inner.CaseWhen.Result, d)
		case *pg_query.Node_CoalesceExpr:
			for _, a := range inner.CoalesceExpr.Args {
				if c := findColInExpr(a, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_MinMaxExpr:
			for _, a := range inner.MinMaxExpr.Args {
				if c := findColInExpr(a, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_RowExpr:
			for _, a := range inner.RowExpr.Args {
				if c := findColInExpr(a, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_AArrayExpr:
			for _, el := range inner.AArrayExpr.Elements {
				if c := findColInExpr(el, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_AIndirection:
			if c := findColInExpr(inner.AIndirection.Arg, d); c != "" {
				return c
			}
			for _, ind := range inner.AIndirection.Indirection {
				if c := findColInExpr(ind, d); c != "" {
					return c
				}
			}
		// PG 16/17 SQL/JSON & SQL/XML expressions
		case *pg_query.Node_JsonObjectConstructor:
			for _, e := range inner.JsonObjectConstructor.Exprs {
				if c := findColInExpr(e, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_JsonArrayConstructor:
			for _, e := range inner.JsonArrayConstructor.Exprs {
				if c := findColInExpr(e, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_JsonArrayQueryConstructor:
			return findColInExpr(inner.JsonArrayQueryConstructor.Query, d)
		case *pg_query.Node_JsonKeyValue:
			if c := findColInExpr(inner.JsonKeyValue.Key, d); c != "" {
				return c
			}
			if inner.JsonKeyValue.Value != nil {
				if c := findColInExpr(inner.JsonKeyValue.Value.RawExpr, d); c != "" {
					return c
				}
				return findColInExpr(inner.JsonKeyValue.Value.FormattedExpr, d)
			}
		case *pg_query.Node_JsonValueExpr:
			if c := findColInExpr(inner.JsonValueExpr.RawExpr, d); c != "" {
				return c
			}
			return findColInExpr(inner.JsonValueExpr.FormattedExpr, d)
		case *pg_query.Node_JsonObjectAgg:
			if inner.JsonObjectAgg.Arg != nil {
				if c := findColInExpr(inner.JsonObjectAgg.Arg.Key, d); c != "" {
					return c
				}
				if inner.JsonObjectAgg.Arg.Value != nil {
					if c := findColInExpr(inner.JsonObjectAgg.Arg.Value.RawExpr, d); c != "" {
						return c
					}
				}
			}
			if inner.JsonObjectAgg.Constructor != nil {
				return findColInExpr(inner.JsonObjectAgg.Constructor.AggFilter, d)
			}
		case *pg_query.Node_JsonArrayAgg:
			if inner.JsonArrayAgg.Arg != nil {
				if c := findColInExpr(inner.JsonArrayAgg.Arg.RawExpr, d); c != "" {
					return c
				}
			}
			if inner.JsonArrayAgg.Constructor != nil {
				return findColInExpr(inner.JsonArrayAgg.Constructor.AggFilter, d)
			}
		case *pg_query.Node_JsonFuncExpr:
			if inner.JsonFuncExpr.ContextItem != nil {
				if c := findColInExpr(inner.JsonFuncExpr.ContextItem.RawExpr, d); c != "" {
					return c
				}
			}
			for _, p := range inner.JsonFuncExpr.Passing {
				if c := findColInExpr(p, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_XmlExpr:
			for _, a := range inner.XmlExpr.Args {
				if c := findColInExpr(a, d); c != "" {
					return c
				}
			}
			for _, na := range inner.XmlExpr.NamedArgs {
				if c := findColInExpr(na, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_XmlSerialize:
			return findColInExpr(inner.XmlSerialize.Expr, d)
		case *pg_query.Node_SubLink:
			if c := findColInExpr(inner.SubLink.Testexpr, d); c != "" {
				return c
			}
			return findColInExpr(inner.SubLink.Subselect, d)
		case *pg_query.Node_SelectStmt:
			if c, _, _ := walkStmt(n, d); c != "" {
				return c
			}
		case *pg_query.Node_List:
			for _, item := range inner.List.Items {
				if c := findColInExpr(item, d); c != "" {
					return c
				}
			}
		case *pg_query.Node_ResTarget:
			return findColInExpr(inner.ResTarget.Val, d)
		case *pg_query.Node_SortBy:
			return findColInExpr(inner.SortBy.Node, d)
		}
		return ""
	}

	// findWholeRowRef detects `SELECT c FROM customers c`, `SELECT c::text FROM customers c`,
	// `SELECT row_to_json(c) FROM customers c`, or `SELECT to_jsonb(customers) FROM customers`.
	var findWholeRowRef func(n *pg_query.Node, rels map[string]bool, depth int) string
	findWholeRowRef = func(n *pg_query.Node, rels map[string]bool, depth int) string {
		if n == nil || len(rels) == 0 || depth > 32 {
			return ""
		}
		d := depth + 1
		switch inner := n.Node.(type) {
		case *pg_query.Node_ResTarget:
			return findWholeRowRef(inner.ResTarget.Val, rels, d)
		case *pg_query.Node_ColumnRef:
			if len(inner.ColumnRef.Fields) == 1 {
				if s := inner.ColumnRef.Fields[0].GetString_(); s != nil {
					name := strings.ToLower(s.Sval)
					if rels[name] {
						return name
					}
				}
			}
		case *pg_query.Node_TypeCast:
			return findWholeRowRef(inner.TypeCast.Arg, rels, d)
		case *pg_query.Node_FuncCall:
			for _, a := range inner.FuncCall.Args {
				if r := findWholeRowRef(a, rels, d); r != "" {
					return r
				}
			}
		case *pg_query.Node_RowExpr:
			for _, a := range inner.RowExpr.Args {
				if r := findWholeRowRef(a, rels, d); r != "" {
					return r
				}
			}
		case *pg_query.Node_JsonObjectConstructor:
			for _, e := range inner.JsonObjectConstructor.Exprs {
				if r := findWholeRowRef(e, rels, d); r != "" {
					return r
				}
			}
		case *pg_query.Node_JsonArrayConstructor:
			for _, e := range inner.JsonArrayConstructor.Exprs {
				if r := findWholeRowRef(e, rels, d); r != "" {
					return r
				}
			}
		case *pg_query.Node_JsonKeyValue:
			if inner.JsonKeyValue.Value != nil {
				return findWholeRowRef(inner.JsonKeyValue.Value.RawExpr, rels, d)
			}
		case *pg_query.Node_JsonValueExpr:
			return findWholeRowRef(inner.JsonValueExpr.RawExpr, rels, d)
		case *pg_query.Node_XmlExpr:
			for _, a := range inner.XmlExpr.Args {
				if r := findWholeRowRef(a, rels, d); r != "" {
					return r
				}
			}
		case *pg_query.Node_XmlSerialize:
			return findWholeRowRef(inner.XmlSerialize.Expr, rels, d)
		}
		return ""
	}

	var checkTargetsForTransform func(n *pg_query.Node, rels map[string]bool, depth int) (string, string, string)
	checkTargetsForTransform = func(n *pg_query.Node, rels map[string]bool, depth int) (string, string, string) {
		if n == nil || depth > maxASTDepth {
			return "", "", ""
		}
		d := depth + 1
		switch inner := n.Node.(type) {
		case *pg_query.Node_ResTarget:
			if rel := findWholeRowRef(inner.ResTarget.Val, rels, 0); rel != "" {
				return rel, "pii_whole_row_exfiltration", "whole-row record projection/serialization"
			}
			return checkTargetsForTransform(inner.ResTarget.Val, rels, d)
		case *pg_query.Node_FuncCall:
			if c := findColInExpr(inner.FuncCall.AggFilter, d); c != "" {
				return c, "pii_side_channel_inference", "aggregate FILTER predicate"
			}
			if inner.FuncCall.Over != nil {
				for _, p := range inner.FuncCall.Over.PartitionClause {
					if c := findColInExpr(p, d); c != "" {
						return c, "pii_side_channel_inference", "WINDOW PARTITION BY clause"
					}
				}
				for _, o := range inner.FuncCall.Over.OrderClause {
					if c := findColInExpr(o, d); c != "" {
						return c, "pii_side_channel_inference", "WINDOW ORDER BY clause"
					}
				}
			}
			if len(inner.FuncCall.Funcname) > 0 {
				last := inner.FuncCall.Funcname[len(inner.FuncCall.Funcname)-1]
				if s := last.GetString_(); s != nil {
					fn := strings.ToLower(s.Sval)
					if piiExfilFuncs[fn] {
						for _, arg := range inner.FuncCall.Args {
							if c := findColInExpr(arg, d); c != "" {
								return c, "pii_side_channel_inference", fmt.Sprintf("expression function %s()", fn)
							}
						}
					}
				}
			}
			for _, arg := range inner.FuncCall.Args {
				if c, r, v := checkTargetsForTransform(arg, rels, d); c != "" {
					return c, r, v
				}
			}
		case *pg_query.Node_AExpr:
			if c := findColInExpr(n, d); c != "" {
				opLabel := inner.AExpr.Kind.String()
				if len(inner.AExpr.Name) > 0 {
					if s := inner.AExpr.Name[len(inner.AExpr.Name)-1].GetString_(); s != nil {
						opLabel = s.Sval
					}
				}
				return c, "pii_side_channel_inference", fmt.Sprintf("projection operator %q", opLabel)
			}
		case *pg_query.Node_CaseExpr:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "CASE projection"
			}
		case *pg_query.Node_CoalesceExpr:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "COALESCE projection"
			}
		case *pg_query.Node_MinMaxExpr:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "GREATEST/LEAST projection"
			}
		case *pg_query.Node_TypeCast:
			if isRiskyCast(inner.TypeCast) {
				if c := findColInExpr(inner.TypeCast.Arg, d); c != "" {
					return c, "pii_side_channel_inference", "binary/numeric/json type cast"
				}
			}
			return checkTargetsForTransform(inner.TypeCast.Arg, rels, d)
		case *pg_query.Node_JsonObjectConstructor, *pg_query.Node_JsonArrayConstructor,
			*pg_query.Node_JsonObjectAgg, *pg_query.Node_JsonArrayAgg,
			*pg_query.Node_JsonFuncExpr, *pg_query.Node_JsonArrayQueryConstructor:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "SQL/JSON serialization expression"
			}
		case *pg_query.Node_XmlExpr, *pg_query.Node_XmlSerialize:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "SQL/XML serialization expression"
			}
		case *pg_query.Node_NamedArgExpr:
			return checkTargetsForTransform(inner.NamedArgExpr.Arg, rels, d)
		case *pg_query.Node_RowExpr:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "ROW() composite projection"
			}
		case *pg_query.Node_AArrayExpr:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "ARRAY[] projection"
			}
		case *pg_query.Node_AIndirection:
			if c := findColInExpr(n, d); c != "" {
				return c, "pii_side_channel_inference", "subscript/field indirection"
			}
		case *pg_query.Node_SubLink:
			return walkStmt(inner.SubLink.Subselect, d)
		}
		return "", "", ""
	}

	// leftmostTargets returns the target list for positional ORDER BY k / GROUP BY k resolution (including UNION).
	var leftmostTargets func(s *pg_query.SelectStmt) []*pg_query.Node
	leftmostTargets = func(s *pg_query.SelectStmt) []*pg_query.Node {
		if s == nil {
			return nil
		}
		if len(s.TargetList) > 0 {
			return s.TargetList
		}
		if s.Larg != nil {
			return leftmostTargets(s.Larg)
		}
		return nil
	}

	checkPositionalIndex := func(node *pg_query.Node, targets []*pg_query.Node, clauseName string) (string, string, string) {
		if node == nil || len(targets) == 0 {
			return "", "", ""
		}
		expr := node
		if sb := node.GetSortBy(); sb != nil {
			expr = sb.Node
		}
		if ac := expr.GetAConst(); ac != nil {
			if iv := ac.GetIval(); iv != nil {
				idx := int(iv.Ival) - 1
				if idx >= 0 && idx < len(targets) {
					if c := findColInExpr(targets[idx], 0); c != "" {
						return c, "pii_side_channel_inference", fmt.Sprintf("%s positional index %d", clauseName, iv.Ival)
					}
				}
			}
		}
		return "", "", ""
	}

	walkStmt = func(n *pg_query.Node, depth int) (string, string, string) {
		if n == nil || depth > maxASTDepth {
			return "", "", ""
		}
		d := depth + 1
		switch inner := n.Node.(type) {
		case *pg_query.Node_SelectStmt:
			s := inner.SelectStmt
			rels := collectRelationNames(s.FromClause)
			targets := leftmostTargets(s)

			if s.WithClause != nil {
				for _, cte := range s.WithClause.Ctes {
					if cteNode := cte.GetCommonTableExpr(); cteNode != nil {
						if c, r, v := walkStmt(cteNode.Ctequery, d); c != "" {
							return c, r, v
						}
					}
				}
			}
			for _, dc := range s.DistinctClause {
				if c := findColInExpr(dc, d); c != "" {
					return c, "pii_side_channel_inference", "DISTINCT ON clause"
				}
			}
			if c := findColInExpr(s.WhereClause, d); c != "" {
				return c, "pii_side_channel_inference", "WHERE predicate"
			}
			if c := findColInExpr(s.HavingClause, d); c != "" {
				return c, "pii_side_channel_inference", "HAVING predicate"
			}
			for _, w := range s.WindowClause {
				if c := findColInExpr(w, d); c != "" {
					return c, "pii_side_channel_inference", "WINDOW clause"
				}
			}
			for _, sb := range s.SortClause {
				if c := findColInExpr(sb, d); c != "" {
					return c, "pii_side_channel_inference", "ORDER BY clause"
				}
				if c, r, v := checkPositionalIndex(sb, targets, "ORDER BY"); c != "" {
					return c, r, v
				}
			}
			for _, gb := range s.GroupClause {
				if c := findColInExpr(gb, d); c != "" {
					return c, "pii_side_channel_inference", "GROUP BY clause"
				}
				if c, r, v := checkPositionalIndex(gb, targets, "GROUP BY"); c != "" {
					return c, r, v
				}
			}
			if c := findColInExpr(s.LimitCount, d); c != "" {
				return c, "pii_side_channel_inference", "LIMIT expression"
			}
			if c := findColInExpr(s.LimitOffset, d); c != "" {
				return c, "pii_side_channel_inference", "OFFSET expression"
			}
			for _, tl := range s.TargetList {
				if c, r, v := checkTargetsForTransform(tl, rels, d); c != "" {
					return c, r, v
				}
			}
			for _, vl := range s.ValuesLists {
				if c := findColInExpr(vl, d); c != "" {
					return c, "pii_side_channel_inference", "VALUES clause"
				}
			}
			for _, fc := range s.FromClause {
				if c, r, v := walkStmt(fc, d); c != "" {
					return c, r, v
				}
			}
			if s.Larg != nil {
				if c, r, v := walkStmt(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Larg}}, d); c != "" {
					return c, r, v
				}
			}
			if s.Rarg != nil {
				if c, r, v := walkStmt(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Rarg}}, d); c != "" {
					return c, r, v
				}
			}
		case *pg_query.Node_ExplainStmt:
			return walkStmt(inner.ExplainStmt.Query, d)
		case *pg_query.Node_PrepareStmt:
			return walkStmt(inner.PrepareStmt.Query, d)
		case *pg_query.Node_DeclareCursorStmt:
			return walkStmt(inner.DeclareCursorStmt.Query, d)
		case *pg_query.Node_UpdateStmt:
			upd := inner.UpdateStmt
			if upd.WithClause != nil {
				for _, cte := range upd.WithClause.Ctes {
					if cn := cte.GetCommonTableExpr(); cn != nil {
						if c, r, v := walkStmt(cn.Ctequery, d); c != "" {
							return c, r, v
						}
					}
				}
			}
			if c := findColInExpr(upd.WhereClause, d); c != "" {
				return c, "pii_side_channel_inference", "UPDATE WHERE predicate"
			}
			for _, r := range upd.ReturningList {
				if c, rule, v := checkTargetsForTransform(r, nil, d); c != "" {
					return c, rule, v
				}
			}
		case *pg_query.Node_DeleteStmt:
			del := inner.DeleteStmt
			if del.WithClause != nil {
				for _, cte := range del.WithClause.Ctes {
					if cn := cte.GetCommonTableExpr(); cn != nil {
						if c, r, v := walkStmt(cn.Ctequery, d); c != "" {
							return c, r, v
						}
					}
				}
			}
			if c := findColInExpr(del.WhereClause, d); c != "" {
				return c, "pii_side_channel_inference", "DELETE WHERE predicate"
			}
			for _, r := range del.ReturningList {
				if c, rule, v := checkTargetsForTransform(r, nil, d); c != "" {
					return c, rule, v
				}
			}
		case *pg_query.Node_InsertStmt:
			ins := inner.InsertStmt
			if ins.WithClause != nil {
				for _, cte := range ins.WithClause.Ctes {
					if cn := cte.GetCommonTableExpr(); cn != nil {
						if c, r, v := walkStmt(cn.Ctequery, d); c != "" {
							return c, r, v
						}
					}
				}
			}
			if c, r, v := walkStmt(ins.SelectStmt, d); c != "" {
				return c, r, v
			}
			for _, r := range ins.ReturningList {
				if c, rule, v := checkTargetsForTransform(r, nil, d); c != "" {
					return c, rule, v
				}
			}
		case *pg_query.Node_MergeStmt:
			if c := findColInExpr(inner.MergeStmt.JoinCondition, d); c != "" {
				return c, "pii_side_channel_inference", "MERGE ON predicate"
			}
		case *pg_query.Node_RangeSubselect:
			return walkStmt(inner.RangeSubselect.Subquery, d)
		case *pg_query.Node_RangeTableFunc:
			if c := findColInExpr(inner.RangeTableFunc.Docexpr, d); c != "" {
				return c, "pii_side_channel_inference", "XMLTABLE expression"
			}
		case *pg_query.Node_JsonTable:
			if inner.JsonTable.ContextItem != nil {
				if c := findColInExpr(inner.JsonTable.ContextItem.RawExpr, d); c != "" {
					return c, "pii_side_channel_inference", "JSON_TABLE expression"
				}
			}
		case *pg_query.Node_JoinExpr:
			if c := findColInExpr(inner.JoinExpr.Quals, d); c != "" {
				return c, "pii_side_channel_inference", "JOIN ON predicate"
			}
			for _, u := range inner.JoinExpr.UsingClause {
				if s := u.GetString_(); s != nil && protected[strings.ToLower(s.Sval)] {
					return strings.ToLower(s.Sval), "pii_side_channel_inference", "JOIN USING clause"
				}
			}
			if c, r, v := walkStmt(inner.JoinExpr.Larg, d); c != "" {
				return c, r, v
			}
			return walkStmt(inner.JoinExpr.Rarg, d)
		}
		return "", "", ""
	}

	for _, raw := range tree.Stmts {
		if raw != nil && raw.Stmt != nil {
			if c, r, v := walkStmt(raw.Stmt, 0); c != "" {
				return c, r, v
			}
		}
	}
	return "", "", ""
}

// collectExprColRefs extracts all referenced column names from an AST expression (including scalar subqueries).
func collectExprColRefs(n *pg_query.Node, out *[]string, depth int) bool {
	if n == nil || depth > 32 {
		return false
	}
	d := depth + 1
	hasStar := false
	switch inner := n.Node.(type) {
	case *pg_query.Node_ResTarget:
		return collectExprColRefs(inner.ResTarget.Val, out, d)
	case *pg_query.Node_ColumnRef:
		for _, f := range inner.ColumnRef.Fields {
			if f.GetAStar() != nil {
				return true
			}
		}
		if len(inner.ColumnRef.Fields) > 0 {
			last := inner.ColumnRef.Fields[len(inner.ColumnRef.Fields)-1]
			if s := last.GetString_(); s != nil {
				*out = append(*out, strings.ToLower(s.Sval))
			}
		}
	case *pg_query.Node_TypeCast:
		return collectExprColRefs(inner.TypeCast.Arg, out, d)
	case *pg_query.Node_FuncCall:
		for _, a := range inner.FuncCall.Args {
			if collectExprColRefs(a, out, d) {
				hasStar = true
			}
		}
	case *pg_query.Node_CoalesceExpr:
		for _, a := range inner.CoalesceExpr.Args {
			if collectExprColRefs(a, out, d) {
				hasStar = true
			}
		}
	case *pg_query.Node_AExpr:
		if collectExprColRefs(inner.AExpr.Lexpr, out, d) {
			hasStar = true
		}
		if collectExprColRefs(inner.AExpr.Rexpr, out, d) {
			hasStar = true
		}
	case *pg_query.Node_CaseExpr:
		if collectExprColRefs(inner.CaseExpr.Arg, out, d) {
			hasStar = true
		}
		for _, w := range inner.CaseExpr.Args {
			if collectExprColRefs(w, out, d) {
				hasStar = true
			}
		}
		if collectExprColRefs(inner.CaseExpr.Defresult, out, d) {
			hasStar = true
		}
	case *pg_query.Node_CaseWhen:
		if collectExprColRefs(inner.CaseWhen.Expr, out, d) {
			hasStar = true
		}
		if collectExprColRefs(inner.CaseWhen.Result, out, d) {
			hasStar = true
		}
	case *pg_query.Node_SubLink:
		// Scalar subquery in SELECT list: `(SELECT full_name FROM customers ... LIMIT 1) AS x`
		if inner.SubLink.Subselect != nil {
			if sel := inner.SubLink.Subselect.GetSelectStmt(); sel != nil && len(sel.TargetList) > 0 {
				if collectExprColRefs(sel.TargetList[0], out, d) {
					hasStar = true
				}
			}
		}
	}
	return hasStar
}

// extractTargetProvenance resolves transitive column provenance across direct aliases,
// multi-level CTEs, subqueries, scalar subqueries, and UNION/INTERSECT/EXCEPT branches so
// aliased or UNION-smuggled PII columns (e.g. `SELECT 'hdr' UNION ALL SELECT full_name FROM customers`)
// STILL inherit explicit `column_rules` masking!
func extractTargetProvenance(tree *pg_query.ParseResult) ([][]string, map[string][]string) {
	if tree == nil || len(tree.Stmts) == 0 || tree.Stmts[0] == nil || tree.Stmts[0].Stmt == nil {
		return nil, nil
	}

	// Build transitive alias graph across all CTEs and subqueries in the statement
	aliasGraph := make(map[string][]string)
	var gatherAliases func(n *pg_query.Node, depth int)
	gatherAliases = func(n *pg_query.Node, depth int) {
		if n == nil || depth > 32 {
			return
		}
		d := depth + 1
		switch inner := n.Node.(type) {
		case *pg_query.Node_SelectStmt:
			s := inner.SelectStmt
			if s.WithClause != nil {
				for _, cte := range s.WithClause.Ctes {
					if cn := cte.GetCommonTableExpr(); cn != nil {
						gatherAliases(cn.Ctequery, d)
						if len(cn.Aliascolnames) > 0 && cn.Ctequery != nil {
							if sel := cn.Ctequery.GetSelectStmt(); sel != nil {
								for idx, ac := range cn.Aliascolnames {
									if sNode := ac.GetString_(); sNode != nil && idx < len(sel.TargetList) {
										var src []string
										collectExprColRefs(sel.TargetList[idx], &src, 0)
										if len(src) > 0 {
											k := strings.ToLower(sNode.Sval)
											aliasGraph[k] = append(aliasGraph[k], src...)
										}
									}
								}
							}
						}
					}
				}
			}
			for _, tl := range s.TargetList {
				if rt := tl.GetResTarget(); rt != nil && rt.Name != "" {
					var src []string
					collectExprColRefs(rt.Val, &src, 0)
					if len(src) > 0 {
						k := strings.ToLower(rt.Name)
						aliasGraph[k] = append(aliasGraph[k], src...)
					}
				}
			}
			for _, fc := range s.FromClause {
				gatherAliases(fc, d)
			}
			if s.Larg != nil {
				gatherAliases(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Larg}}, d)
			}
			if s.Rarg != nil {
				gatherAliases(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Rarg}}, d)
			}
		case *pg_query.Node_RangeSubselect:
			gatherAliases(inner.RangeSubselect.Subquery, d)
		case *pg_query.Node_JoinExpr:
			gatherAliases(inner.JoinExpr.Larg, d)
			gatherAliases(inner.JoinExpr.Rarg, d)
		}
	}
	gatherAliases(tree.Stmts[0].Stmt, 0)

	expandTransitive := func(initial []string) []string {
		seen := make(map[string]bool, len(initial)+4)
		queue := make([]string, 0, len(initial)+4)
		for _, c := range initial {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
		for i := 0; i < len(queue) && len(queue) < 32; i++ {
			for _, next := range aliasGraph[queue[i]] {
				if !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
		return queue
	}

	// Recursively merge positional targets across UNION / INTERSECT / EXCEPT branches!
	var mergeSelectTargets func(s *pg_query.SelectStmt, depth int) ([][]string, map[string][]string, bool)
	mergeSelectTargets = func(s *pg_query.SelectStmt, depth int) ([][]string, map[string][]string, bool) {
		if s == nil || depth > 16 {
			return nil, nil, false
		}
		if s.Larg != nil || s.Rarg != nil {
			lp, la, lStar := mergeSelectTargets(s.Larg, depth+1)
			rp, ra, rStar := mergeSelectTargets(s.Rarg, depth+1)
			aliases := make(map[string][]string)
			for k, v := range la {
				aliases[k] = append(aliases[k], v...)
			}
			for k, v := range ra {
				aliases[k] = append(aliases[k], v...)
			}
			if lStar || rStar {
				return nil, aliases, true
			}
			n := max(len(lp), len(rp))
			merged := make([][]string, n)
			for i := 0; i < n; i++ {
				var combined []string
				if i < len(lp) {
					combined = append(combined, lp[i]...)
				}
				if i < len(rp) {
					combined = append(combined, rp[i]...)
				}
				merged[i] = expandTransitive(combined)
			}
			return merged, aliases, false
		}
		if len(s.TargetList) == 0 {
			return nil, nil, false
		}
		hasStar := false
		positional := make([][]string, len(s.TargetList))
		aliases := make(map[string][]string)
		for i, t := range s.TargetList {
			rt := t.GetResTarget()
			if rt == nil {
				continue
			}
			var cols []string
			if collectExprColRefs(rt.Val, &cols, 0) {
				hasStar = true
			}
			expanded := expandTransitive(cols)
			positional[i] = expanded
			if rt.Name != "" && len(expanded) > 0 {
				aliases[strings.ToLower(rt.Name)] = expanded
			}
		}
		if hasStar {
			return nil, aliases, true
		}
		return positional, aliases, false
	}

	switch s := tree.Stmts[0].Stmt.Node.(type) {
	case *pg_query.Node_SelectStmt:
		pos, ali, _ := mergeSelectTargets(s.SelectStmt, 0)
		return pos, ali
	case *pg_query.Node_InsertStmt:
		return extractReturningProvenance(s.InsertStmt.ReturningList, expandTransitive)
	case *pg_query.Node_UpdateStmt:
		return extractReturningProvenance(s.UpdateStmt.ReturningList, expandTransitive)
	case *pg_query.Node_DeleteStmt:
		return extractReturningProvenance(s.DeleteStmt.ReturningList, expandTransitive)
	default:
		return nil, nil
	}
}

func extractReturningProvenance(targets []*pg_query.Node, expand func([]string) []string) ([][]string, map[string][]string) {
	if len(targets) == 0 {
		return nil, nil
	}
	hasStar := false
	positional := make([][]string, len(targets))
	aliases := make(map[string][]string)
	for i, t := range targets {
		rt := t.GetResTarget()
		if rt == nil {
			continue
		}
		var cols []string
		if collectExprColRefs(rt.Val, &cols, 0) {
			hasStar = true
		}
		expanded := expand(cols)
		positional[i] = expanded
		if rt.Name != "" && len(expanded) > 0 {
			aliases[strings.ToLower(rt.Name)] = expanded
		}
	}
	if hasStar {
		return nil, aliases
	}
	return positional, aliases
}
