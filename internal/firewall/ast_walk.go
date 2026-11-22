package firewall

import (
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

type astAnalysis struct {
	primaryType       string
	allTypes          []string
	tables            []string
	dangerousFuncs    []string
	isDDL             bool
	writeWithoutWhere bool
	hasCopyProgram    bool
	hasCopyOut        bool
	hasDoBlock        bool
	hasRoleEscalation bool
	hasSelectStar     bool
	depthExceeded     bool
}

// isKnownNonDDLTopLevel returns true ONLY for top-level PostgreSQL statements that are
// non-DDL queries, DML, transactions, or session commands. Any unrecognized top-level statement
// fails closed as DDL when `block_ddl: true` is active.
func isKnownNonDDLTopLevel(n *pg_query.Node) bool {
	if n == nil {
		return true
	}
	switch n.Node.(type) {
	case *pg_query.Node_SelectStmt,
		*pg_query.Node_InsertStmt,
		*pg_query.Node_UpdateStmt,
		*pg_query.Node_DeleteStmt,
		*pg_query.Node_MergeStmt,
		*pg_query.Node_ExplainStmt,
		*pg_query.Node_VariableShowStmt,
		*pg_query.Node_VariableSetStmt,
		*pg_query.Node_TransactionStmt,
		*pg_query.Node_DeallocateStmt,
		*pg_query.Node_DiscardStmt,
		*pg_query.Node_ClosePortalStmt,
		*pg_query.Node_DeclareCursorStmt,
		*pg_query.Node_FetchStmt,
		*pg_query.Node_PrepareStmt,
		*pg_query.Node_ExecuteStmt,
		*pg_query.Node_CallStmt,
		*pg_query.Node_CopyStmt,
		*pg_query.Node_DoStmt,
		*pg_query.Node_ListenStmt,
		*pg_query.Node_UnlistenStmt,
		*pg_query.Node_NotifyStmt:
		return true
	default:
		return false
	}
}

func analyzeAST(tree *pg_query.ParseResult) astAnalysis {
	var res astAnalysis
	tableSeen := make(map[string]bool)
	funcSeen := make(map[string]bool)
	typeSeen := make(map[string]bool)

	addType := func(t string) {
		if res.primaryType == "" {
			res.primaryType = t
		}
		if !typeSeen[t] {
			typeSeen[t] = true
			res.allTypes = append(res.allTypes, t)
		}
	}
	addTable := func(rv *pg_query.RangeVar) {
		if rv == nil || rv.Relname == "" {
			return
		}
		name := rv.Relname
		if rv.Schemaname != "" {
			name = rv.Schemaname + "." + rv.Relname
		}
		low := strings.ToLower(name)
		if !tableSeen[low] {
			tableSeen[low] = true
			res.tables = append(res.tables, low)
		}
	}
	addFunc := func(fn *pg_query.FuncCall) {
		if fn == nil || len(fn.Funcname) == 0 {
			return
		}
		last := fn.Funcname[len(fn.Funcname)-1]
		if s := last.GetString_(); s != nil {
			name := strings.ToLower(s.Sval)
			if dangerousFunctions[name] && !funcSeen[name] {
				funcSeen[name] = true
				res.dangerousFuncs = append(res.dangerousFuncs, name)
			}
		}
	}

	var walkNode func(n *pg_query.Node, depth int)
	walkNode = func(n *pg_query.Node, depth int) {
		if n == nil || res.depthExceeded {
			return
		}
		if depth > maxASTDepth {
			res.depthExceeded = true
			return
		}
		d := depth + 1

		switch inner := n.Node.(type) {
		case *pg_query.Node_SelectStmt:
			s := inner.SelectStmt
			addType("SELECT")
			if s.IntoClause != nil {
				res.isDDL = true
				addTable(s.IntoClause.Rel)
			}
			if s.WithClause != nil {
				for _, cte := range s.WithClause.Ctes {
					walkNode(cte, d)
				}
			}
			for _, dc := range s.DistinctClause {
				walkNode(dc, d)
			}
			for _, tl := range s.TargetList {
				walkNode(tl, d)
			}
			for _, fc := range s.FromClause {
				walkNode(fc, d)
			}
			walkNode(s.WhereClause, d)
			for _, g := range s.GroupClause {
				walkNode(g, d)
			}
			walkNode(s.HavingClause, d)
			for _, w := range s.WindowClause {
				walkNode(w, d)
			}
			for _, vl := range s.ValuesLists {
				walkNode(vl, d)
			}
			for _, sc := range s.SortClause {
				walkNode(sc, d)
			}
			walkNode(s.LimitCount, d)
			walkNode(s.LimitOffset, d)
			if s.Larg != nil {
				walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Larg}}, d)
			}
			if s.Rarg != nil {
				walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Rarg}}, d)
			}

		case *pg_query.Node_InsertStmt:
			ins := inner.InsertStmt
			addType("INSERT")
			addTable(ins.Relation)
			if ins.WithClause != nil {
				for _, cte := range ins.WithClause.Ctes {
					walkNode(cte, d)
				}
			}
			walkNode(ins.SelectStmt, d)
			for _, r := range ins.ReturningList {
				walkNode(r, d)
			}

		case *pg_query.Node_UpdateStmt:
			upd := inner.UpdateStmt
			addType("UPDATE")
			addTable(upd.Relation)
			if upd.WhereClause == nil || isTautology(upd.WhereClause) {
				res.writeWithoutWhere = true
			}
			if upd.WithClause != nil {
				for _, cte := range upd.WithClause.Ctes {
					walkNode(cte, d)
				}
			}
			for _, t := range upd.TargetList {
				walkNode(t, d)
			}
			for _, fc := range upd.FromClause {
				walkNode(fc, d)
			}
			walkNode(upd.WhereClause, d)
			for _, r := range upd.ReturningList {
				walkNode(r, d)
			}

		case *pg_query.Node_DeleteStmt:
			del := inner.DeleteStmt
			addType("DELETE")
			addTable(del.Relation)
			if del.WhereClause == nil || isTautology(del.WhereClause) {
				res.writeWithoutWhere = true
			}
			if del.WithClause != nil {
				for _, cte := range del.WithClause.Ctes {
					walkNode(cte, d)
				}
			}
			for _, u := range del.UsingClause {
				walkNode(u, d)
			}
			walkNode(del.WhereClause, d)
			for _, r := range del.ReturningList {
				walkNode(r, d)
			}

		case *pg_query.Node_MergeStmt:
			ms := inner.MergeStmt
			addType("MERGE")
			addTable(ms.Relation)
			if ms.JoinCondition == nil || isTautology(ms.JoinCondition) {
				res.writeWithoutWhere = true
			}
			walkNode(ms.SourceRelation, d)
			walkNode(ms.JoinCondition, d)
			if ms.WithClause != nil {
				for _, cte := range ms.WithClause.Ctes {
					walkNode(cte, d)
				}
			}
			for _, mc := range ms.MergeWhenClauses {
				walkNode(mc, d)
			}

		case *pg_query.Node_MergeWhenClause:
			walkNode(inner.MergeWhenClause.Condition, d)
			for _, t := range inner.MergeWhenClause.TargetList {
				walkNode(t, d)
			}
			for _, v := range inner.MergeWhenClause.Values {
				walkNode(v, d)
			}

		case *pg_query.Node_DropStmt:
			addType("DROP")
			res.isDDL = true
			for _, obj := range inner.DropStmt.Objects {
				extractDropTable(obj, addTable)
			}

		case *pg_query.Node_TruncateStmt:
			addType("TRUNCATE")
			res.isDDL = true
			for _, rel := range inner.TruncateStmt.Relations {
				walkNode(rel, d)
			}

		case *pg_query.Node_AlterTableStmt:
			addType("ALTER")
			res.isDDL = true
			addTable(inner.AlterTableStmt.Relation)

		case *pg_query.Node_RenameStmt:
			addType("RENAME")
			res.isDDL = true
			addTable(inner.RenameStmt.Relation)

		case *pg_query.Node_AlterOwnerStmt:
			addType("ALTER_OWNER")
			res.isDDL = true
			addTable(inner.AlterOwnerStmt.Relation)

		case *pg_query.Node_CreateStmt:
			addType("CREATE")
			res.isDDL = true
			addTable(inner.CreateStmt.Relation)

		case *pg_query.Node_CreateTableAsStmt:
			addType("CREATE_TABLE_AS")
			res.isDDL = true
			if inner.CreateTableAsStmt.Into != nil {
				addTable(inner.CreateTableAsStmt.Into.Rel)
			}
			walkNode(inner.CreateTableAsStmt.Query, d)

		case *pg_query.Node_IndexStmt:
			addType("CREATE_INDEX")
			res.isDDL = true
			addTable(inner.IndexStmt.Relation)

		case *pg_query.Node_ViewStmt:
			addType("CREATE_VIEW")
			res.isDDL = true
			addTable(inner.ViewStmt.View)
			walkNode(inner.ViewStmt.Query, d)

		case *pg_query.Node_CreateFunctionStmt:
			addType("CREATE_FUNCTION")
			res.isDDL = true

		case *pg_query.Node_GrantStmt:
			addType("GRANT")
			res.isDDL = true

		case *pg_query.Node_GrantRoleStmt:
			addType("GRANT_ROLE")
			res.isDDL = true

		case *pg_query.Node_AlterSystemStmt:
			addType("ALTER_SYSTEM")
			res.isDDL = true

		case *pg_query.Node_DropOwnedStmt:
			addType("DROP_OWNED")
			res.isDDL = true

		case *pg_query.Node_CreateSubscriptionStmt, *pg_query.Node_AlterSubscriptionStmt, *pg_query.Node_DropSubscriptionStmt,
			*pg_query.Node_CreatePublicationStmt, *pg_query.Node_AlterPublicationStmt:
			addType("REPLICATION_DDL")
			res.isDDL = true

		case *pg_query.Node_CreateFdwStmt, *pg_query.Node_AlterFdwStmt,
			*pg_query.Node_CreateForeignServerStmt, *pg_query.Node_AlterForeignServerStmt,
			*pg_query.Node_CreateUserMappingStmt, *pg_query.Node_AlterUserMappingStmt, *pg_query.Node_DropUserMappingStmt,
			*pg_query.Node_CreateForeignTableStmt, *pg_query.Node_ImportForeignSchemaStmt:
			addType("FDW_DDL")
			res.isDDL = true

		case *pg_query.Node_CreateRoleStmt, *pg_query.Node_AlterRoleStmt, *pg_query.Node_DropRoleStmt,
			*pg_query.Node_AlterRoleSetStmt, *pg_query.Node_CreatedbStmt, *pg_query.Node_DropdbStmt,
			*pg_query.Node_AlterDatabaseStmt, *pg_query.Node_AlterDatabaseSetStmt,
			*pg_query.Node_CreateSchemaStmt, *pg_query.Node_AlterObjectSchemaStmt,
			*pg_query.Node_CreateExtensionStmt, *pg_query.Node_AlterExtensionStmt, *pg_query.Node_AlterExtensionContentsStmt,
			*pg_query.Node_CreateTrigStmt, *pg_query.Node_CreateEventTrigStmt, *pg_query.Node_AlterEventTrigStmt,
			*pg_query.Node_CreatePolicyStmt, *pg_query.Node_AlterPolicyStmt, *pg_query.Node_RuleStmt,
			*pg_query.Node_AlterDefaultPrivilegesStmt, *pg_query.Node_RefreshMatViewStmt,
			*pg_query.Node_CreateSeqStmt, *pg_query.Node_AlterSeqStmt,
			*pg_query.Node_CreateDomainStmt, *pg_query.Node_AlterDomainStmt,
			*pg_query.Node_CreateEnumStmt, *pg_query.Node_AlterEnumStmt,
			*pg_query.Node_CompositeTypeStmt, *pg_query.Node_CreateRangeStmt, *pg_query.Node_DefineStmt,
			*pg_query.Node_CreateTableSpaceStmt, *pg_query.Node_DropTableSpaceStmt, *pg_query.Node_AlterTableSpaceOptionsStmt,
			*pg_query.Node_AlterFunctionStmt, *pg_query.Node_ReassignOwnedStmt, *pg_query.Node_CommentStmt,
			*pg_query.Node_SecLabelStmt, *pg_query.Node_CreateStatsStmt, *pg_query.Node_AlterStatsStmt,
			*pg_query.Node_VacuumStmt, *pg_query.Node_ReindexStmt, *pg_query.Node_ClusterStmt,
			*pg_query.Node_LockStmt, *pg_query.Node_CheckPointStmt:
			addType("DDL")
			res.isDDL = true

		case *pg_query.Node_LoadStmt:
			addType("LOAD")
			res.isDDL = true
			res.hasCopyProgram = true

		case *pg_query.Node_CopyStmt:
			addType("COPY")
			addTable(inner.CopyStmt.Relation)
			walkNode(inner.CopyStmt.Query, d)
			if inner.CopyStmt.IsProgram || inner.CopyStmt.Filename != "" {
				res.hasCopyProgram = true
			}
			if !inner.CopyStmt.IsFrom {
				res.hasCopyOut = true
			}

		case *pg_query.Node_DoStmt:
			addType("DO")
			res.hasDoBlock = true

		case *pg_query.Node_ExplainStmt:
			addType("EXPLAIN")
			walkNode(inner.ExplainStmt.Query, d)

		case *pg_query.Node_VariableShowStmt:
			addType("SHOW")

		case *pg_query.Node_VariableSetStmt:
			addType("SET")
			vname := strings.ToLower(inner.VariableSetStmt.Name)
			if vname == "role" || vname == "session_authorization" ||
				vname == "row_security" || vname == "session_replication_role" ||
				vname == "default_transaction_read_only" ||
				inner.VariableSetStmt.Kind == pg_query.VariableSetKind_VAR_RESET_ALL {
				res.hasRoleEscalation = true
			}

		case *pg_query.Node_PrepareStmt:
			addType("PREPARE")
			walkNode(inner.PrepareStmt.Query, d)

		case *pg_query.Node_ExecuteStmt:
			addType("EXECUTE")

		case *pg_query.Node_CallStmt:
			addType("CALL")
			if inner.CallStmt.Funccall != nil {
				addFunc(inner.CallStmt.Funccall)
				for _, arg := range inner.CallStmt.Funccall.Args {
					walkNode(arg, d)
				}
			}

		case *pg_query.Node_DeclareCursorStmt:
			addType("DECLARE_CURSOR")
			walkNode(inner.DeclareCursorStmt.Query, d)

		case *pg_query.Node_FetchStmt:
			addType("FETCH")

		case *pg_query.Node_ClosePortalStmt:
			addType("CLOSE")

		case *pg_query.Node_ListenStmt:
			addType("LISTEN")

		case *pg_query.Node_UnlistenStmt:
			addType("UNLISTEN")

		case *pg_query.Node_NotifyStmt:
			addType("NOTIFY")

		case *pg_query.Node_TransactionStmt:
			switch inner.TransactionStmt.Kind {
			case pg_query.TransactionStmtKind_TRANS_STMT_BEGIN, pg_query.TransactionStmtKind_TRANS_STMT_START:
				addType("BEGIN")
			case pg_query.TransactionStmtKind_TRANS_STMT_COMMIT:
				addType("COMMIT")
			case pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK, pg_query.TransactionStmtKind_TRANS_STMT_ROLLBACK_TO:
				addType("ROLLBACK")
			case pg_query.TransactionStmtKind_TRANS_STMT_SAVEPOINT:
				addType("SAVEPOINT")
			case pg_query.TransactionStmtKind_TRANS_STMT_RELEASE:
				addType("RELEASE")
			default:
				addType("TRANSACTION")
			}

		case *pg_query.Node_DeallocateStmt:
			addType("DEALLOCATE")

		case *pg_query.Node_DiscardStmt:
			addType("DISCARD")

		// Sub-clauses & expression nodes
		case *pg_query.Node_CommonTableExpr:
			walkNode(inner.CommonTableExpr.Ctequery, d)

		case *pg_query.Node_RangeVar:
			addTable(inner.RangeVar)

		case *pg_query.Node_RangeSubselect:
			walkNode(inner.RangeSubselect.Subquery, d)

		case *pg_query.Node_RangeFunction:
			for _, f := range inner.RangeFunction.Functions {
				walkNode(f, d)
			}

		case *pg_query.Node_RangeTableFunc:
			walkNode(inner.RangeTableFunc.Docexpr, d)
			walkNode(inner.RangeTableFunc.Rowexpr, d)
			for _, c := range inner.RangeTableFunc.Columns {
				walkNode(c, d)
			}

		case *pg_query.Node_JsonTable:
			if inner.JsonTable.ContextItem != nil {
				walkNode(inner.JsonTable.ContextItem.RawExpr, d)
				walkNode(inner.JsonTable.ContextItem.FormattedExpr, d)
			}
			for _, p := range inner.JsonTable.Passing {
				walkNode(p, d)
			}

		case *pg_query.Node_JoinExpr:
			walkNode(inner.JoinExpr.Larg, d)
			walkNode(inner.JoinExpr.Rarg, d)
			walkNode(inner.JoinExpr.Quals, d)

		case *pg_query.Node_ResTarget:
			walkNode(inner.ResTarget.Val, d)

		case *pg_query.Node_ColumnRef:
			for _, f := range inner.ColumnRef.Fields {
				if f.GetAStar() != nil {
					res.hasSelectStar = true
				}
			}

		case *pg_query.Node_FuncCall:
			addFunc(inner.FuncCall)
			for _, arg := range inner.FuncCall.Args {
				walkNode(arg, d)
			}
			walkNode(inner.FuncCall.AggFilter, d)
			if inner.FuncCall.Over != nil {
				walkNode(&pg_query.Node{Node: &pg_query.Node_WindowDef{WindowDef: inner.FuncCall.Over}}, d)
			}

		case *pg_query.Node_WindowDef:
			for _, p := range inner.WindowDef.PartitionClause {
				walkNode(p, d)
			}
			for _, o := range inner.WindowDef.OrderClause {
				walkNode(o, d)
			}
			walkNode(inner.WindowDef.StartOffset, d)
			walkNode(inner.WindowDef.EndOffset, d)

		case *pg_query.Node_SortBy:
			walkNode(inner.SortBy.Node, d)

		case *pg_query.Node_AExpr:
			walkNode(inner.AExpr.Lexpr, d)
			walkNode(inner.AExpr.Rexpr, d)

		case *pg_query.Node_BoolExpr:
			for _, arg := range inner.BoolExpr.Args {
				walkNode(arg, d)
			}

		case *pg_query.Node_SubLink:
			walkNode(inner.SubLink.Subselect, d)
			walkNode(inner.SubLink.Testexpr, d)

		case *pg_query.Node_TypeCast:
			walkNode(inner.TypeCast.Arg, d)

		case *pg_query.Node_CaseExpr:
			walkNode(inner.CaseExpr.Arg, d)
			for _, w := range inner.CaseExpr.Args {
				walkNode(w, d)
			}
			walkNode(inner.CaseExpr.Defresult, d)

		case *pg_query.Node_CaseWhen:
			walkNode(inner.CaseWhen.Expr, d)
			walkNode(inner.CaseWhen.Result, d)

		case *pg_query.Node_CoalesceExpr:
			for _, a := range inner.CoalesceExpr.Args {
				walkNode(a, d)
			}

		case *pg_query.Node_MinMaxExpr:
			for _, a := range inner.MinMaxExpr.Args {
				walkNode(a, d)
			}

		case *pg_query.Node_NullTest:
			walkNode(inner.NullTest.Arg, d)

		case *pg_query.Node_BooleanTest:
			walkNode(inner.BooleanTest.Arg, d)

		case *pg_query.Node_NamedArgExpr:
			walkNode(inner.NamedArgExpr.Arg, d)

		case *pg_query.Node_AArrayExpr:
			for _, el := range inner.AArrayExpr.Elements {
				walkNode(el, d)
			}

		case *pg_query.Node_RowExpr:
			for _, a := range inner.RowExpr.Args {
				walkNode(a, d)
			}

		case *pg_query.Node_AIndirection:
			walkNode(inner.AIndirection.Arg, d)
			for _, ind := range inner.AIndirection.Indirection {
				walkNode(ind, d)
			}

		// PG 16/17 SQL/JSON & SQL/XML expressions
		case *pg_query.Node_JsonObjectConstructor:
			for _, e := range inner.JsonObjectConstructor.Exprs {
				walkNode(e, d)
			}
		case *pg_query.Node_JsonArrayConstructor:
			for _, e := range inner.JsonArrayConstructor.Exprs {
				walkNode(e, d)
			}
		case *pg_query.Node_JsonArrayQueryConstructor:
			walkNode(inner.JsonArrayQueryConstructor.Query, d)
		case *pg_query.Node_JsonKeyValue:
			walkNode(inner.JsonKeyValue.Key, d)
			if inner.JsonKeyValue.Value != nil {
				walkNode(inner.JsonKeyValue.Value.RawExpr, d)
				walkNode(inner.JsonKeyValue.Value.FormattedExpr, d)
			}
		case *pg_query.Node_JsonValueExpr:
			walkNode(inner.JsonValueExpr.RawExpr, d)
			walkNode(inner.JsonValueExpr.FormattedExpr, d)
		case *pg_query.Node_JsonObjectAgg:
			if inner.JsonObjectAgg.Arg != nil {
				walkNode(inner.JsonObjectAgg.Arg.Key, d)
				if inner.JsonObjectAgg.Arg.Value != nil {
					walkNode(inner.JsonObjectAgg.Arg.Value.RawExpr, d)
				}
			}
			if inner.JsonObjectAgg.Constructor != nil {
				walkNode(inner.JsonObjectAgg.Constructor.AggFilter, d)
			}
		case *pg_query.Node_JsonArrayAgg:
			if inner.JsonArrayAgg.Arg != nil {
				walkNode(inner.JsonArrayAgg.Arg.RawExpr, d)
			}
			if inner.JsonArrayAgg.Constructor != nil {
				walkNode(inner.JsonArrayAgg.Constructor.AggFilter, d)
			}
		case *pg_query.Node_JsonFuncExpr:
			if inner.JsonFuncExpr.ContextItem != nil {
				walkNode(inner.JsonFuncExpr.ContextItem.RawExpr, d)
			}
			for _, p := range inner.JsonFuncExpr.Passing {
				walkNode(p, d)
			}
		case *pg_query.Node_XmlExpr:
			for _, a := range inner.XmlExpr.Args {
				walkNode(a, d)
			}
			for _, na := range inner.XmlExpr.NamedArgs {
				walkNode(na, d)
			}
		case *pg_query.Node_XmlSerialize:
			walkNode(inner.XmlSerialize.Expr, d)

		case *pg_query.Node_List:
			for _, item := range inner.List.Items {
				walkNode(item, d)
			}
		}
	}

	for _, raw := range tree.Stmts {
		if raw != nil && raw.Stmt != nil {
			// Fail-closed DDL guarantee: any unrecognized top-level PG statement is treated as DDL
			if !isKnownNonDDLTopLevel(raw.Stmt) {
				res.isDDL = true
			}
			walkNode(raw.Stmt, 0)
		}
	}

	// If a SELECT wraps a modifying CTE (WITH d AS (DELETE ...) SELECT ...), elevate primaryType so audit & HITL reflect the write!
	for _, st := range res.allTypes {
		if st == "DELETE" || st == "UPDATE" || st == "INSERT" || st == "MERGE" {
			res.primaryType = st
			break
		}
	}

	if res.primaryType == "" {
		res.primaryType = "OTHER"
	}
	return res
}

func extractDropTable(obj *pg_query.Node, addTable func(*pg_query.RangeVar)) {
	if obj == nil {
		return
	}
	if list := obj.GetList(); list != nil && len(list.Items) > 0 {
		parts := make([]string, 0, len(list.Items))
		for _, item := range list.Items {
			if s := item.GetString_(); s != nil {
				parts = append(parts, s.Sval)
			}
		}
		if len(parts) == 1 {
			addTable(&pg_query.RangeVar{Relname: parts[0]})
		} else if len(parts) >= 2 {
			addTable(&pg_query.RangeVar{Schemaname: parts[0], Relname: parts[1]})
		}
	}
}

// isTautology detects trivially always-true WHERE/ON predicates including constant arithmetic
// folding (1+1=2), comparisons (2>1, 1<>2), self-equality (id=id, id IS NOT DISTINCT FROM id),
// BETWEEN/IN/LIKE constants, NULL/Boolean tests, COALESCE/CASE, uncorrelated EXISTS (SELECT 1),
// and recursive negations of contradictions.
func isTautology(n *pg_query.Node) bool {
	return isTautologyDepth(n, 0)
}

func isTautologyDepth(n *pg_query.Node, depth int) bool {
	if n == nil {
		return true
	}
	if depth > 32 {
		return false
	}
	d := depth + 1

	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if b := v.AConst.GetBoolval(); b != nil && b.Boolval {
			return true
		}
		if iv := v.AConst.GetIval(); iv != nil && iv.Ival != 0 {
			return true
		}
	case *pg_query.Node_TypeCast:
		return isTautologyDepth(v.TypeCast.Arg, d)
	case *pg_query.Node_NullTest:
		if v.NullTest.Nulltesttype == pg_query.NullTestType_IS_NOT_NULL {
			if ac := v.NullTest.Arg.GetAConst(); ac != nil && !ac.Isnull {
				return true
			}
			if _, ok := evalConstInt(v.NullTest.Arg, 0); ok {
				return true
			}
		}
		if v.NullTest.Nulltesttype == pg_query.NullTestType_IS_NULL {
			if ac := v.NullTest.Arg.GetAConst(); ac != nil && ac.Isnull {
				return true
			}
		}
	case *pg_query.Node_BooleanTest:
		switch v.BooleanTest.Booltesttype {
		case pg_query.BoolTestType_IS_TRUE, pg_query.BoolTestType_IS_NOT_FALSE:
			return isTautologyDepth(v.BooleanTest.Arg, d)
		case pg_query.BoolTestType_IS_FALSE, pg_query.BoolTestType_IS_NOT_TRUE:
			return isContradictionDepth(v.BooleanTest.Arg, d)
		}
	case *pg_query.Node_CoalesceExpr:
		for _, a := range v.CoalesceExpr.Args {
			if ac := a.GetAConst(); ac != nil && ac.Isnull {
				continue
			}
			return isTautologyDepth(a, d)
		}
	case *pg_query.Node_CaseExpr:
		// CASE WHEN <tautology> THEN <tautology> ...
		if v.CaseExpr.Arg == nil && len(v.CaseExpr.Args) > 0 {
			if cw := v.CaseExpr.Args[0].GetCaseWhen(); cw != nil {
				if isTautologyDepth(cw.Expr, d) && isTautologyDepth(cw.Result, d) {
					return true
				}
			}
		}
	case *pg_query.Node_SubLink:
		// Uncorrelated constant `EXISTS (SELECT 1)` with no FROM or WHERE clause is always true
		if v.SubLink.SubLinkType == pg_query.SubLinkType_EXISTS_SUBLINK && v.SubLink.Subselect != nil {
			if sel := v.SubLink.Subselect.GetSelectStmt(); sel != nil {
				if len(sel.FromClause) == 0 && sel.WhereClause == nil && len(sel.TargetList) > 0 {
					return true
				}
			}
		}
	case *pg_query.Node_BoolExpr:
		switch v.BoolExpr.Boolop {
		case pg_query.BoolExprType_OR_EXPR:
			for _, arg := range v.BoolExpr.Args {
				if isTautologyDepth(arg, d) {
					return true
				}
			}
		case pg_query.BoolExprType_AND_EXPR:
			allTrue := len(v.BoolExpr.Args) > 0
			for _, arg := range v.BoolExpr.Args {
				if !isTautologyDepth(arg, d) {
					allTrue = false
					break
				}
			}
			return allTrue
		case pg_query.BoolExprType_NOT_EXPR:
			if len(v.BoolExpr.Args) == 1 {
				return isContradictionDepth(v.BoolExpr.Args[0], d)
			}
		}
	case *pg_query.Node_AExpr:
		switch v.AExpr.Kind {
		case pg_query.A_Expr_Kind_AEXPR_OP:
			if len(v.AExpr.Name) == 1 {
				if op := v.AExpr.Name[0].GetString_(); op != nil {
					if evalConstComparison(op.Sval, v.AExpr.Lexpr, v.AExpr.Rexpr) == 1 {
						return true
					}
					if (op.Sval == "=" || op.Sval == ">=" || op.Sval == "<=") && sameColumnRef(v.AExpr.Lexpr, v.AExpr.Rexpr) {
						return true
					}
				}
			}
		case pg_query.A_Expr_Kind_AEXPR_NOT_DISTINCT:
			if evalConstComparison("=", v.AExpr.Lexpr, v.AExpr.Rexpr) == 1 || sameColumnRef(v.AExpr.Lexpr, v.AExpr.Rexpr) {
				return true
			}
		case pg_query.A_Expr_Kind_AEXPR_IN:
			if list := v.AExpr.Rexpr.GetList(); list != nil {
				for _, item := range list.Items {
					if evalConstComparison("=", v.AExpr.Lexpr, item) == 1 || sameColumnRef(v.AExpr.Lexpr, item) {
						return true
					}
				}
			}
		case pg_query.A_Expr_Kind_AEXPR_BETWEEN, pg_query.A_Expr_Kind_AEXPR_BETWEEN_SYM:
			if list := v.AExpr.Rexpr.GetList(); list != nil && len(list.Items) == 2 {
				val, okV := evalConstInt(v.AExpr.Lexpr, 0)
				lo, okL := evalConstInt(list.Items[0], 0)
				hi, okH := evalConstInt(list.Items[1], 0)
				if okV && okL && okH {
					if v.AExpr.Kind == pg_query.A_Expr_Kind_AEXPR_BETWEEN_SYM && lo > hi {
						lo, hi = hi, lo
					}
					if val >= lo && val <= hi {
						return true
					}
				}
			}
		case pg_query.A_Expr_Kind_AEXPR_LIKE, pg_query.A_Expr_Kind_AEXPR_ILIKE:
			// Constant `'a' LIKE '%'`
			if l := v.AExpr.Lexpr.GetAConst(); l != nil && l.GetSval() != nil {
				if r := v.AExpr.Rexpr.GetAConst(); r != nil && r.GetSval() != nil {
					if r.GetSval().Sval == "%" || r.GetSval().Sval == l.GetSval().Sval {
						return true
					}
				}
			}
		}
	}
	return false
}

func isContradictionDepth(n *pg_query.Node, depth int) bool {
	if n == nil || depth > 32 {
		return false
	}
	d := depth + 1
	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if b := v.AConst.GetBoolval(); b != nil && !b.Boolval {
			return true
		}
		if iv := v.AConst.GetIval(); iv != nil && iv.Ival == 0 {
			return true
		}
	case *pg_query.Node_TypeCast:
		return isContradictionDepth(v.TypeCast.Arg, d)
	case *pg_query.Node_BoolExpr:
		switch v.BoolExpr.Boolop {
		case pg_query.BoolExprType_AND_EXPR:
			for _, a := range v.BoolExpr.Args {
				if isContradictionDepth(a, d) {
					return true
				}
			}
		case pg_query.BoolExprType_OR_EXPR:
			allFalse := len(v.BoolExpr.Args) > 0
			for _, a := range v.BoolExpr.Args {
				if !isContradictionDepth(a, d) {
					allFalse = false
					break
				}
			}
			return allFalse
		case pg_query.BoolExprType_NOT_EXPR:
			if len(v.BoolExpr.Args) == 1 {
				return isTautologyDepth(v.BoolExpr.Args[0], d)
			}
		}
	case *pg_query.Node_AExpr:
		if v.AExpr.Kind == pg_query.A_Expr_Kind_AEXPR_OP && len(v.AExpr.Name) == 1 {
			if op := v.AExpr.Name[0].GetString_(); op != nil {
				if evalConstComparison(op.Sval, v.AExpr.Lexpr, v.AExpr.Rexpr) == -1 {
					return true
				}
				if (op.Sval == "<>" || op.Sval == "!=" || op.Sval == "<" || op.Sval == ">") && sameColumnRef(v.AExpr.Lexpr, v.AExpr.Rexpr) {
					return true
				}
			}
		}
	}
	return false
}

// evalConstInt folds constant integer arithmetic expressions (+, -, *, /, unary -) safely.
func evalConstInt(n *pg_query.Node, depth int) (int64, bool) {
	if n == nil || depth > 16 {
		return 0, false
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if iv := v.AConst.GetIval(); iv != nil {
			return int64(iv.Ival), true
		}
	case *pg_query.Node_TypeCast:
		return evalConstInt(v.TypeCast.Arg, depth+1)
	case *pg_query.Node_AExpr:
		if v.AExpr.Kind != pg_query.A_Expr_Kind_AEXPR_OP || len(v.AExpr.Name) != 1 {
			return 0, false
		}
		opNode := v.AExpr.Name[0].GetString_()
		if opNode == nil {
			return 0, false
		}
		// Unary minus / plus
		if v.AExpr.Lexpr == nil {
			r, ok := evalConstInt(v.AExpr.Rexpr, depth+1)
			if !ok {
				return 0, false
			}
			if opNode.Sval == "-" {
				return -r, true
			}
			if opNode.Sval == "+" {
				return r, true
			}
			return 0, false
		}
		l, okL := evalConstInt(v.AExpr.Lexpr, depth+1)
		r, okR := evalConstInt(v.AExpr.Rexpr, depth+1)
		if !okL || !okR {
			return 0, false
		}
		switch opNode.Sval {
		case "+":
			return l + r, true
		case "-":
			return l - r, true
		case "*":
			return l * r, true
		case "/":
			if r == 0 {
				return 0, false
			}
			return l / r, true
		case "%":
			if r == 0 {
				return 0, false
			}
			return l % r, true
		}
	}
	return 0, false
}

// evalConstComparison returns 1 if constant op evaluates true, -1 if false, 0 if non-constant/unknown.
func evalConstComparison(op string, a, b *pg_query.Node) int {
	if a == nil || b == nil {
		return 0
	}
	if l, okL := evalConstInt(a, 0); okL {
		if r, okR := evalConstInt(b, 0); okR {
			var ok bool
			switch op {
			case "=":
				ok = l == r
			case "<>", "!=":
				ok = l != r
			case ">":
				ok = l > r
			case ">=":
				ok = l >= r
			case "<":
				ok = l < r
			case "<=":
				ok = l <= r
			default:
				return 0
			}
			if ok {
				return 1
			}
			return -1
		}
	}
	ac, bc := a.GetAConst(), b.GetAConst()
	if ac == nil || bc == nil {
		return 0
	}
	if as, bs := ac.GetSval(), bc.GetSval(); as != nil && bs != nil {
		var ok bool
		switch op {
		case "=":
			ok = as.Sval == bs.Sval
		case "<>", "!=":
			ok = as.Sval != bs.Sval
		case ">":
			ok = as.Sval > bs.Sval
		case ">=":
			ok = as.Sval >= bs.Sval
		case "<":
			ok = as.Sval < bs.Sval
		case "<=":
			ok = as.Sval <= bs.Sval
		default:
			return 0
		}
		if ok {
			return 1
		}
		return -1
	}
	if ab, bb := ac.GetBoolval(), bc.GetBoolval(); ab != nil && bb != nil {
		var ok bool
		switch op {
		case "=":
			ok = ab.Boolval == bb.Boolval
		case "<>", "!=":
			ok = ab.Boolval != bb.Boolval
		default:
			return 0
		}
		if ok {
			return 1
		}
		return -1
	}
	return 0
}

func sameColumnRef(a, b *pg_query.Node) bool {
	if a == nil || b == nil {
		return false
	}
	ca, cb := a.GetColumnRef(), b.GetColumnRef()
	if ca == nil || cb == nil || len(ca.Fields) == 0 || len(ca.Fields) != len(cb.Fields) {
		return false
	}
	for i := range ca.Fields {
		sa, sb := ca.Fields[i].GetString_(), cb.Fields[i].GetString_()
		if sa == nil || sb == nil || !strings.EqualFold(sa.Sval, sb.Sval) {
			return false
		}
	}
	return true
}
