//go:build cgo

package policy

import (
	"errors"
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

var dangerousFilterFuncs = map[string]bool{
	"pg_read_file": true, "pg_read_binary_file": true, "pg_execute_server_program": true,
	"pg_ls_dir": true, "pg_stat_file": true, "lo_import": true, "lo_export": true,
	"dblink": true, "dblink_exec": true, "dblink_connect": true, "set_config": true,
	"query_to_xml": true, "table_to_xml": true, "pg_sleep": true, "pg_sleep_for": true,
	"pg_terminate_backend": true, "pg_cancel_backend": true, "setval": true,
}

func validateRowFilter(rf RowFilterPolicy) error {
	tbl := strings.TrimSpace(rf.Table)
	pred := strings.TrimSpace(rf.Predicate)
	if tbl == "" {
		return errors.New("table cannot be empty")
	}
	if pred == "" {
		return errors.New("predicate cannot be empty")
	}
	if strings.IndexByte(pred, 0) >= 0 {
		return errors.New("predicate contains embedded NUL byte")
	}
	sample := pred
	for _, ph := range []string{"{{db_user}}", "{{database}}", "{{application_name}}", "{{profile}}"} {
		sample = strings.ReplaceAll(sample, ph, "__pgveil_sample__")
	}
	tree, err := pg_query.Parse("SELECT 1 WHERE " + sample)
	if err != nil {
		return fmt.Errorf("invalid SQL predicate %q: %w", pred, err)
	}
	if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		return fmt.Errorf("predicate %q must be a single boolean expression", pred)
	}
	sel := tree.Stmts[0].Stmt.GetSelectStmt()
	if sel == nil || sel.WhereClause == nil || len(sel.FromClause) > 0 || len(sel.GroupClause) > 0 || sel.LimitCount != nil {
		return fmt.Errorf("predicate %q must be a pure WHERE expression without extra clauses", pred)
	}
	return checkPredicateExprSafe(sel.WhereClause, 0)
}

func checkPredicateExprSafe(n *pg_query.Node, depth int) error {
	if n == nil {
		return nil
	}
	if depth > 64 {
		return errors.New("predicate expression nesting depth exceeded")
	}
	switch x := n.Node.(type) {
	case *pg_query.Node_SubLink:
		return errors.New("subqueries are not permitted inside row_filters predicates")
	case *pg_query.Node_FuncCall:
		if x.FuncCall != nil {
			var parts []string
			for _, f := range x.FuncCall.Funcname {
				if s := f.GetString_(); s != nil {
					parts = append(parts, strings.ToLower(s.Sval))
				}
			}
			if len(parts) > 0 {
				fn := parts[len(parts)-1]
				if dangerousFilterFuncs[fn] || strings.HasPrefix(fn, "lo_") || strings.HasPrefix(fn, "dblink") {
					return fmt.Errorf("dangerous function %q is not permitted in row_filters predicate", fn)
				}
			}
			for _, a := range x.FuncCall.Args {
				if err := checkPredicateExprSafe(a, depth+1); err != nil {
					return err
				}
			}
		}
	case *pg_query.Node_BoolExpr:
		for _, a := range x.BoolExpr.Args {
			if err := checkPredicateExprSafe(a, depth+1); err != nil {
				return err
			}
		}
	case *pg_query.Node_AExpr:
		if err := checkPredicateExprSafe(x.AExpr.Lexpr, depth+1); err != nil {
			return err
		}
		if err := checkPredicateExprSafe(x.AExpr.Rexpr, depth+1); err != nil {
			return err
		}
	case *pg_query.Node_NullTest:
		return checkPredicateExprSafe(x.NullTest.Arg, depth+1)
	case *pg_query.Node_BooleanTest:
		return checkPredicateExprSafe(x.BooleanTest.Arg, depth+1)
	case *pg_query.Node_TypeCast:
		return checkPredicateExprSafe(x.TypeCast.Arg, depth+1)
	case *pg_query.Node_CoalesceExpr:
		for _, a := range x.CoalesceExpr.Args {
			if err := checkPredicateExprSafe(a, depth+1); err != nil {
				return err
			}
		}
	case *pg_query.Node_CaseExpr:
		if err := checkPredicateExprSafe(x.CaseExpr.Arg, depth+1); err != nil {
			return err
		}
		for _, w := range x.CaseExpr.Args {
			if cw := w.GetCaseWhen(); cw != nil {
				if err := checkPredicateExprSafe(cw.Expr, depth+1); err != nil {
					return err
				}
				if err := checkPredicateExprSafe(cw.Result, depth+1); err != nil {
					return err
				}
			}
		}
		return checkPredicateExprSafe(x.CaseExpr.Defresult, depth+1)
	case *pg_query.Node_List:
		for _, it := range x.List.Items {
			if err := checkPredicateExprSafe(it, depth+1); err != nil {
				return err
			}
		}
	case *pg_query.Node_AArrayExpr:
		for _, el := range x.AArrayExpr.Elements {
			if err := checkPredicateExprSafe(el, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}
