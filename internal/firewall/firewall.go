package firewall

import (
	"fmt"
	"strings"

	"github.com/duhanguler/pgveil/internal/policy"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// Action is the firewall's enforcement verdict for a SQL query.
type Action string

const (
	ActionAllow       Action = "ALLOW"
	ActionBlock       Action = "BLOCK"
	ActionRequireHITL Action = "REQUIRE_HITL"
)

// Decision holds the full AST inspection result for policy enforcement and auditing.
type Decision struct {
	Action        Action              `json:"action"`
	StatementType string              `json:"statement_type"`
	RiskLevel     string              `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
	Reason        string              `json:"reason"`
	Rule          string              `json:"rule"`
	Tables        []string            `json:"tables"`
	Fingerprint   string              `json:"fingerprint"`
	HasSelectStar bool                `json:"has_select_star"`
	TargetSources [][]string          `json:"-"` // Positional source column provenance per SELECT target (prevents alias masking bypasses)
	AliasSources  map[string][]string `json:"-"` // Lowercased output alias -> referenced source columns
}

// dangerousFunctions are PostgreSQL server-side functions that enable filesystem read/write,
// OS command execution, SSRF/lateral movement, denied-table bypasses, privilege escalation, or DoS.
var dangerousFunctions = map[string]bool{
	"pg_read_file":                       true,
	"pg_read_binary_file":                true,
	"pg_ls_dir":                          true,
	"pg_ls_logdir":                       true,
	"pg_ls_waldir":                       true,
	"pg_ls_tmpdir":                       true,
	"pg_ls_archive_statusdir":            true,
	"pg_ls_logicalmapdir":                true,
	"pg_ls_logicalsnapdir":               true,
	"pg_ls_replslotdir":                  true,
	"pg_stat_file":                       true,
	"pg_execute_server_program":          true,
	"lo_import":                          true,
	"lo_export":                          true,
	"lo_from_bytea":                      true,
	"lo_put":                             true,
	"lo_get":                             true,
	"lo_open":                            true,
	"lo_create":                          true,
	"lo_unlink":                          true,
	"loread":                             true,
	"lowrite":                            true,
	"dblink":                             true,
	"dblink_exec":                        true,
	"dblink_connect":                     true,
	"dblink_connect_u":                   true,
	"query_to_xml":                       true,
	"query_to_xmlschema":                 true,
	"query_to_xml_and_xmlschema":         true,
	"table_to_xml":                       true,
	"table_to_xmlschema":                 true,
	"table_to_xml_and_xmlschema":         true,
	"schema_to_xml":                      true,
	"schema_to_xmlschema":                true,
	"schema_to_xml_and_xmlschema":        true,
	"database_to_xml":                    true,
	"database_to_xmlschema":              true,
	"database_to_xml_and_xmlschema":      true,
	"cursor_to_xml":                      true,
	"cursor_to_xmlschema":                true,
	"set_config":                         true,
	"pg_terminate_backend":               true,
	"pg_cancel_backend":                  true,
	"pg_reload_conf":                     true,
	"pg_rotate_logfile":                  true,
	"pg_switch_wal":                      true,
	"pg_export_snapshot":                 true,
	"pg_logical_emit_message":            true,
	"pg_logical_slot_get_changes":        true,
	"pg_logical_slot_peek_changes":       true,
	"pg_logical_slot_get_binary_changes": true,
	"pg_sleep":                           true,
	"pg_sleep_for":                       true,
	"pg_sleep_until":                     true,
}

// sensitiveSystemTables contain credential hashes, raw planner PII samples (pg_stats),
// live cross-session SQL queries (pg_stat_activity), or sensitive server internals.
var sensitiveSystemTables = map[string]bool{
	"pg_shadow":             true,
	"pg_authid":             true,
	"pg_auth_members":       true,
	"pg_roles":              true,
	"pg_user":               true,
	"pg_file_settings":      true,
	"pg_hba_file_rules":     true,
	"pg_stats":              true,
	"pg_statistic":          true,
	"pg_statistic_ext_data": true,
	"pg_stat_activity":      true,
	"pg_stat_statements":    true,
	"pg_settings":           true,
	"pg_config":             true,
	"pg_prepared_statements": true,
	"pg_cursors":            true,
	"pg_shmem_allocations":  true,
}

// safeClientHousekeepingStatements are non-data session commands sent automatically by drivers (pgx, psql, psycopg).
var safeHousekeeping = map[string]bool{
	"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "SAVEPOINT": true,
	"RELEASE": true, "DEALLOCATE": true, "DISCARD": true, "CLOSE": true,
	"LISTEN": true, "UNLISTEN": true,
}

// Evaluate parses sql using PostgreSQL's own AST parser (libpg_query) and enforces the role's FirewallPolicy.
func Evaluate(sql string, profile *policy.RoleProfile) Decision {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || trimmed == ";" {
		return Decision{
			Action:        ActionAllow,
			StatementType: "EMPTY",
			RiskLevel:     "LOW",
			Rule:          "empty_query",
		}
	}

	fp, _ := pg_query.Fingerprint(trimmed)
	if fp == "" {
		fp = "unparseable"
	}

	if profile == nil {
		return Decision{
			Action:        ActionAllow,
			StatementType: "UNKNOWN",
			RiskLevel:     "LOW",
			Fingerprint:   fp,
		}
	}
	fw := profile.Firewall

	// Admin wildcard with all guards disabled fast-path still parses for accurate auditing.
	tree, err := pg_query.Parse(trimmed)
	if err != nil {
		if containsWildcard(fw.AllowStatements) && !fw.BlockMultiStatement {
			return Decision{
				Action:        ActionAllow,
				StatementType: "RAW",
				RiskLevel:     "LOW",
				Fingerprint:   fp,
			}
		}
		return Decision{
			Action:        ActionBlock,
			StatementType: "PARSE_ERROR",
			RiskLevel:     "HIGH",
			Reason:        fmt.Sprintf("SQL syntax rejected by AST parser: %v", err),
			Rule:          "ast_parse_error",
			Fingerprint:   fp,
		}
	}

	if len(tree.Stmts) == 0 {
		return Decision{
			Action:        ActionAllow,
			StatementType: "EMPTY",
			RiskLevel:     "LOW",
			Fingerprint:   fp,
		}
	}

	// 1. Multi-statement SQL injection protection
	if fw.BlockMultiStatement && len(tree.Stmts) > 1 {
		return Decision{
			Action:        ActionBlock,
			StatementType: "MULTI_STATEMENT",
			RiskLevel:     "CRITICAL",
			Reason:        fmt.Sprintf("Multi-statement query (%d statements) blocked by policy", len(tree.Stmts)),
			Rule:          "block_multi_statement",
			Fingerprint:   fp,
		}
	}

	analysis := analyzeAST(tree)
	targetSources, aliasSources := extractTargetProvenance(tree)
	dec := Decision{
		StatementType: analysis.primaryType,
		Tables:        analysis.tables,
		Fingerprint:   fp,
		HasSelectStar: analysis.hasSelectStar,
		TargetSources: targetSources,
		AliasSources:  aliasSources,
		RiskLevel:     "LOW",
	}

	// 2. Dangerous server functions, COPY TO PROGRAM, DO blocks, privilege escalation
	if fw.BlockDangerousFunctions {
		if len(analysis.dangerousFuncs) > 0 {
			dec.Action = ActionBlock
			dec.RiskLevel = "CRITICAL"
			dec.Rule = "block_dangerous_functions"
			dec.Reason = fmt.Sprintf("Dangerous PostgreSQL function blocked: %s", strings.Join(analysis.dangerousFuncs, ", "))
			return dec
		}
		if analysis.hasCopyProgram {
			dec.Action = ActionBlock
			dec.RiskLevel = "CRITICAL"
			dec.Rule = "block_copy_program"
			dec.Reason = "COPY TO/FROM PROGRAM or server filesystem access is blocked"
			return dec
		}
		if analysis.hasDoBlock {
			dec.Action = ActionBlock
			dec.RiskLevel = "CRITICAL"
			dec.Rule = "block_do_block"
			dec.Reason = "Anonymous procedural DO $$ blocks are blocked by policy"
			return dec
		}
		if analysis.hasRoleEscalation {
			dec.Action = ActionBlock
			dec.RiskLevel = "CRITICAL"
			dec.Rule = "block_role_escalation"
			dec.Reason = "SET ROLE / SET SESSION AUTHORIZATION privilege escalation is blocked"
			return dec
		}
	}

	// 3. DDL Blocking (including ALTER SYSTEM, DROP, TRUNCATE, CREATE, GRANT, REVOKE)
	if fw.BlockDDL && analysis.isDDL {
		dec.Action = ActionBlock
		dec.RiskLevel = "CRITICAL"
		dec.Rule = "block_ddl"
		dec.Reason = fmt.Sprintf("DDL / privilege statement (%s) is blocked for profile %q", analysis.primaryType, profile.Name)
		return dec
	}

	// 4. Write without WHERE or tautological WHERE (e.g., DELETE FROM orders WHERE 1=1)
	if fw.BlockWriteWithoutWhere && analysis.writeWithoutWhere {
		dec.Action = ActionBlock
		dec.RiskLevel = "CRITICAL"
		dec.Rule = "block_write_without_where"
		dec.Reason = fmt.Sprintf("Unscoped %s without effective WHERE clause (or tautology like 1=1) is blocked", analysis.primaryType)
		return dec
	}

	// 5. Table Denylist, System Catalog Lockout & Allowlist
	deniedSet := toLowerSet(fw.DeniedTables)
	allowedSet := toLowerSet(fw.AllowedTables)
	for _, tbl := range analysis.tables {
		lt := strings.ToLower(tbl)
		bare := stripSchema(lt)
		if deniedSet[lt] || deniedSet[bare] {
			dec.Action = ActionBlock
			dec.RiskLevel = "HIGH"
			dec.Rule = "denied_table"
			dec.Reason = fmt.Sprintf("Access to restricted table %q is denied for profile %q", tbl, profile.Name)
			return dec
		}
		if fw.BlockSystemCatalogs && (sensitiveSystemTables[bare] || strings.HasPrefix(lt, "pg_catalog.pg_auth") || strings.HasPrefix(lt, "pg_catalog.pg_shadow")) {
			dec.Action = ActionBlock
			dec.RiskLevel = "HIGH"
			dec.Rule = "block_system_catalogs"
			dec.Reason = fmt.Sprintf("Access to sensitive system catalog %q is blocked", tbl)
			return dec
		}
		if len(allowedSet) > 0 && !allowedSet[lt] && !allowedSet[bare] {
			dec.Action = ActionBlock
			dec.RiskLevel = "HIGH"
			dec.Rule = "table_not_allowed"
			dec.Reason = fmt.Sprintf("Table %q is outside allowed_tables for profile %q", tbl, profile.Name)
			return dec
		}
	}

	// 6. PII Side-Channel / Oracle Inference Guard (WHERE tckn LIKE '100%', SUBSTRING(iban,1,6), ORDER BY ssn)
	if fw.BlockPIIInference {
		protected := resolveProtectedColumns(profile)
		if len(protected) > 0 {
			if col, via := detectPIIInference(tree, protected); col != "" {
				dec.Action = ActionBlock
				dec.RiskLevel = "HIGH"
				dec.Rule = "pii_side_channel_inference"
				dec.Reason = fmt.Sprintf("PII side-channel inference blocked: protected column %q referenced in %s", col, via)
				return dec
			}
		}
	}

	// 7. Optional SELECT * guard on tables
	if fw.BlockSelectStarOnPII && analysis.hasSelectStar && len(analysis.tables) > 0 {
		dec.Action = ActionBlock
		dec.RiskLevel = "MEDIUM"
		dec.Rule = "block_select_star"
		dec.Reason = "SELECT * is disabled for this profile; explicitly project required columns"
		return dec
	}

	// 7. Human-in-the-Loop (HITL) Approval Trigger (checks primary statement AND modifying CTEs!)
	hitlSet := toUpperSet(fw.RequireHITLStatements)
	for _, st := range analysis.allTypes {
		if hitlSet[st] {
			dec.Action = ActionRequireHITL
			dec.RiskLevel = "HIGH"
			dec.Rule = "require_hitl_" + strings.ToLower(st)
			dec.Reason = fmt.Sprintf("Statement %s requires Human-in-the-Loop approval for profile %q", st, profile.Name)
			return dec
		}
	}

	// 8. Statement Allowlist (safe transaction housekeeping allowed unless explicitly destructive)
	if !containsWildcard(fw.AllowStatements) {
		allowSet := toUpperSet(fw.AllowStatements)
		for _, st := range analysis.allTypes {
			if allowSet[st] || safeHousekeeping[st] {
				continue
			}
			// Allow benign SET client_encoding / application_name / search_path from drivers
			if st == "SET" && !analysis.hasRoleEscalation {
				continue
			}
			dec.Action = ActionBlock
			dec.RiskLevel = "HIGH"
			dec.Rule = "statement_not_allowed"
			dec.Reason = fmt.Sprintf("Statement type %s is not permitted for profile %q", st, profile.Name)
			return dec
		}
	}

	dec.Action = ActionAllow
	dec.Rule = "policy_allow"
	dec.Reason = "Query passed AST firewall inspection"
	return dec
}

type astAnalysis struct {
	primaryType       string
	allTypes          []string
	tables            []string
	dangerousFuncs    []string
	isDDL             bool
	writeWithoutWhere bool
	hasCopyProgram    bool
	hasDoBlock        bool
	hasRoleEscalation bool
	hasSelectStar     bool
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

	var walkNode func(n *pg_query.Node)
	walkNode = func(n *pg_query.Node) {
		if n == nil {
			return
		}
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
					walkNode(cte)
				}
			}
			for _, d := range s.DistinctClause {
				walkNode(d)
			}
			for _, tl := range s.TargetList {
				walkNode(tl)
			}
			for _, fc := range s.FromClause {
				walkNode(fc)
			}
			walkNode(s.WhereClause)
			for _, g := range s.GroupClause {
				walkNode(g)
			}
			walkNode(s.HavingClause)
			for _, w := range s.WindowClause {
				walkNode(w)
			}
			for _, vl := range s.ValuesLists {
				walkNode(vl)
			}
			for _, sc := range s.SortClause {
				walkNode(sc)
			}
			walkNode(s.LimitCount)
			walkNode(s.LimitOffset)
			if s.Larg != nil {
				walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Larg}})
			}
			if s.Rarg != nil {
				walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Rarg}})
			}

		case *pg_query.Node_InsertStmt:
			ins := inner.InsertStmt
			addType("INSERT")
			addTable(ins.Relation)
			if ins.WithClause != nil {
				for _, cte := range ins.WithClause.Ctes {
					walkNode(cte)
				}
			}
			walkNode(ins.SelectStmt)
			for _, r := range ins.ReturningList {
				walkNode(r)
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
					walkNode(cte)
				}
			}
			for _, t := range upd.TargetList {
				walkNode(t)
			}
			for _, fc := range upd.FromClause {
				walkNode(fc)
			}
			walkNode(upd.WhereClause)
			for _, r := range upd.ReturningList {
				walkNode(r)
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
					walkNode(cte)
				}
			}
			for _, u := range del.UsingClause {
				walkNode(u)
			}
			walkNode(del.WhereClause)
			for _, r := range del.ReturningList {
				walkNode(r)
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
				walkNode(rel)
			}

		case *pg_query.Node_AlterTableStmt:
			addType("ALTER")
			res.isDDL = true
			addTable(inner.AlterTableStmt.Relation)

		case *pg_query.Node_CreateStmt:
			addType("CREATE")
			res.isDDL = true
			addTable(inner.CreateStmt.Relation)

		case *pg_query.Node_IndexStmt:
			addType("CREATE_INDEX")
			res.isDDL = true
			addTable(inner.IndexStmt.Relation)

		case *pg_query.Node_ViewStmt:
			addType("CREATE_VIEW")
			res.isDDL = true
			addTable(inner.ViewStmt.View)
			walkNode(inner.ViewStmt.Query)

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

		case *pg_query.Node_CopyStmt:
			addType("COPY")
			addTable(inner.CopyStmt.Relation)
			walkNode(inner.CopyStmt.Query)
			if inner.CopyStmt.IsProgram || inner.CopyStmt.Filename != "" {
				res.hasCopyProgram = true
			}

		case *pg_query.Node_DoStmt:
			addType("DO")
			res.hasDoBlock = true

		case *pg_query.Node_ExplainStmt:
			addType("EXPLAIN")
			walkNode(inner.ExplainStmt.Query)

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
			walkNode(inner.PrepareStmt.Query)

		case *pg_query.Node_ExecuteStmt:
			addType("EXECUTE")

		case *pg_query.Node_CallStmt:
			addType("CALL")
			if inner.CallStmt.Funccall != nil {
				addFunc(inner.CallStmt.Funccall)
				for _, arg := range inner.CallStmt.Funccall.Args {
					walkNode(arg)
				}
			}

		case *pg_query.Node_MergeStmt:
			addType("MERGE")
			addTable(inner.MergeStmt.Relation)
			walkNode(inner.MergeStmt.SourceRelation)
			walkNode(inner.MergeStmt.JoinCondition)
			if inner.MergeStmt.WithClause != nil {
				for _, cte := range inner.MergeStmt.WithClause.Ctes {
					walkNode(cte)
				}
			}
			for _, mc := range inner.MergeStmt.MergeWhenClauses {
				walkNode(mc)
			}

		case *pg_query.Node_MergeWhenClause:
			walkNode(inner.MergeWhenClause.Condition)
			for _, t := range inner.MergeWhenClause.TargetList {
				walkNode(t)
			}
			for _, v := range inner.MergeWhenClause.Values {
				walkNode(v)
			}

		case *pg_query.Node_DeclareCursorStmt:
			addType("DECLARE_CURSOR")
			walkNode(inner.DeclareCursorStmt.Query)

		case *pg_query.Node_FetchStmt:
			addType("FETCH")

		case *pg_query.Node_CreateTableAsStmt:
			addType("CREATE_TABLE_AS")
			res.isDDL = true
			if inner.CreateTableAsStmt.Into != nil {
				addTable(inner.CreateTableAsStmt.Into.Rel)
			}
			walkNode(inner.CreateTableAsStmt.Query)

		case *pg_query.Node_CreateRoleStmt, *pg_query.Node_AlterRoleStmt, *pg_query.Node_DropRoleStmt,
			*pg_query.Node_CreateExtensionStmt, *pg_query.Node_CreateTrigStmt, *pg_query.Node_CreatePolicyStmt,
			*pg_query.Node_RuleStmt, *pg_query.Node_AlterDefaultPrivilegesStmt, *pg_query.Node_RefreshMatViewStmt,
			*pg_query.Node_VacuumStmt, *pg_query.Node_ReindexStmt, *pg_query.Node_ClusterStmt, *pg_query.Node_LockStmt:
			addType("DDL")
			res.isDDL = true

		case *pg_query.Node_LoadStmt:
			addType("LOAD")
			res.isDDL = true
			res.hasCopyProgram = true

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

		case *pg_query.Node_CommonTableExpr:
			walkNode(inner.CommonTableExpr.Ctequery)

		case *pg_query.Node_RangeVar:
			addTable(inner.RangeVar)

		case *pg_query.Node_RangeSubselect:
			walkNode(inner.RangeSubselect.Subquery)

		case *pg_query.Node_RangeFunction:
			for _, f := range inner.RangeFunction.Functions {
				walkNode(f)
			}

		case *pg_query.Node_JoinExpr:
			walkNode(inner.JoinExpr.Larg)
			walkNode(inner.JoinExpr.Rarg)
			walkNode(inner.JoinExpr.Quals)

		case *pg_query.Node_ResTarget:
			walkNode(inner.ResTarget.Val)

		case *pg_query.Node_ColumnRef:
			for _, f := range inner.ColumnRef.Fields {
				if f.GetAStar() != nil {
					res.hasSelectStar = true
				}
			}

		case *pg_query.Node_FuncCall:
			addFunc(inner.FuncCall)
			for _, arg := range inner.FuncCall.Args {
				walkNode(arg)
			}
			walkNode(inner.FuncCall.AggFilter)
			if inner.FuncCall.Over != nil {
				walkNode(&pg_query.Node{Node: &pg_query.Node_WindowDef{WindowDef: inner.FuncCall.Over}})
			}

		case *pg_query.Node_WindowDef:
			for _, p := range inner.WindowDef.PartitionClause {
				walkNode(p)
			}
			for _, o := range inner.WindowDef.OrderClause {
				walkNode(o)
			}
			walkNode(inner.WindowDef.StartOffset)
			walkNode(inner.WindowDef.EndOffset)

		case *pg_query.Node_SortBy:
			walkNode(inner.SortBy.Node)

		case *pg_query.Node_AExpr:
			walkNode(inner.AExpr.Lexpr)
			walkNode(inner.AExpr.Rexpr)

		case *pg_query.Node_BoolExpr:
			for _, arg := range inner.BoolExpr.Args {
				walkNode(arg)
			}

		case *pg_query.Node_SubLink:
			walkNode(inner.SubLink.Subselect)
			walkNode(inner.SubLink.Testexpr)

		case *pg_query.Node_TypeCast:
			walkNode(inner.TypeCast.Arg)

		case *pg_query.Node_CaseExpr:
			walkNode(inner.CaseExpr.Arg)
			for _, w := range inner.CaseExpr.Args {
				walkNode(w)
			}
			walkNode(inner.CaseExpr.Defresult)

		case *pg_query.Node_CaseWhen:
			walkNode(inner.CaseWhen.Expr)
			walkNode(inner.CaseWhen.Result)

		case *pg_query.Node_CoalesceExpr:
			for _, a := range inner.CoalesceExpr.Args {
				walkNode(a)
			}

		case *pg_query.Node_MinMaxExpr:
			for _, a := range inner.MinMaxExpr.Args {
				walkNode(a)
			}

		case *pg_query.Node_NullTest:
			walkNode(inner.NullTest.Arg)

		case *pg_query.Node_BooleanTest:
			walkNode(inner.BooleanTest.Arg)

		case *pg_query.Node_NamedArgExpr:
			walkNode(inner.NamedArgExpr.Arg)

		case *pg_query.Node_AArrayExpr:
			for _, el := range inner.AArrayExpr.Elements {
				walkNode(el)
			}

		case *pg_query.Node_RowExpr:
			for _, a := range inner.RowExpr.Args {
				walkNode(a)
			}

		case *pg_query.Node_AIndirection:
			walkNode(inner.AIndirection.Arg)
			for _, ind := range inner.AIndirection.Indirection {
				walkNode(ind)
			}

		case *pg_query.Node_List:
			for _, item := range inner.List.Items {
				walkNode(item)
			}
		}
	}

	for _, raw := range tree.Stmts {
		if raw != nil && raw.Stmt != nil {
			walkNode(raw.Stmt)
		}
	}

	// If a SELECT wraps a modifying CTE (WITH d AS (DELETE ...) SELECT ...), elevate primaryType so audit & HITL reflect the write!
	for _, st := range res.allTypes {
		if st == "DELETE" || st == "UPDATE" || st == "INSERT" {
			res.primaryType = st
			break
		}
	}

	if res.primaryType == "" {
		res.primaryType = "OTHER"
	}
	return res
}

// isTautology detects trivially always-true WHERE predicates such as WHERE true, WHERE 1=1,
// WHERE 2>1, WHERE 1<>2, WHERE id=id, WHERE NOT (1=2), or WHERE cond OR 1=1.
func isTautology(n *pg_query.Node) bool {
	if n == nil {
		return true
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if b := v.AConst.GetBoolval(); b != nil && b.Boolval {
			return true
		}
		if iv := v.AConst.GetIval(); iv != nil && iv.Ival != 0 {
			return true
		}
	case *pg_query.Node_TypeCast:
		return isTautology(v.TypeCast.Arg)
	case *pg_query.Node_BoolExpr:
		switch v.BoolExpr.Boolop {
		case pg_query.BoolExprType_OR_EXPR:
			for _, arg := range v.BoolExpr.Args {
				if isTautology(arg) {
					return true
				}
			}
		case pg_query.BoolExprType_AND_EXPR:
			allTrue := len(v.BoolExpr.Args) > 0
			for _, arg := range v.BoolExpr.Args {
				if !isTautology(arg) {
					allTrue = false
					break
				}
			}
			return allTrue
		case pg_query.BoolExprType_NOT_EXPR:
			if len(v.BoolExpr.Args) == 1 {
				return isContradiction(v.BoolExpr.Args[0])
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
		case pg_query.A_Expr_Kind_AEXPR_IN:
			// Catch WHERE 1 IN (1, 2)
			if list := v.AExpr.Rexpr.GetList(); list != nil && v.AExpr.Lexpr.GetAConst() != nil {
				for _, item := range list.Items {
					if sameConstant(v.AExpr.Lexpr, item) {
						return true
					}
				}
			}
		}
	}
	return false
}

func isContradiction(n *pg_query.Node) bool {
	if n == nil {
		return false
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_AConst:
		if b := v.AConst.GetBoolval(); b != nil && !b.Boolval {
			return true
		}
		if iv := v.AConst.GetIval(); iv != nil && iv.Ival == 0 {
			return true
		}
	case *pg_query.Node_TypeCast:
		return isContradiction(v.TypeCast.Arg)
	case *pg_query.Node_AExpr:
		if v.AExpr.Kind == pg_query.A_Expr_Kind_AEXPR_OP && len(v.AExpr.Name) == 1 {
			if op := v.AExpr.Name[0].GetString_(); op != nil {
				return evalConstComparison(op.Sval, v.AExpr.Lexpr, v.AExpr.Rexpr) == -1
			}
		}
	}
	return false
}

// evalConstComparison returns 1 if constant op evaluates true, -1 if false, 0 if non-constant/unknown.
func evalConstComparison(op string, a, b *pg_query.Node) int {
	if a == nil || b == nil {
		return 0
	}
	ac, bc := a.GetAConst(), b.GetAConst()
	if ac == nil || bc == nil {
		return 0
	}
	if ai, bi := ac.GetIval(), bc.GetIval(); ai != nil && bi != nil {
		l, r := ai.Ival, bi.Ival
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

func sameConstant(a, b *pg_query.Node) bool {
	return evalConstComparison("=", a, b) == 1
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

func containsWildcard(list []string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == "*" {
			return true
		}
	}
	return false
}

func toLowerSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		if s := strings.ToLower(strings.TrimSpace(it)); s != "" {
			m[s] = true
		}
	}
	return m
}

func toUpperSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		if s := strings.ToUpper(strings.TrimSpace(it)); s != "" {
			m[s] = true
		}
	}
	return m
}

func stripSchema(name string) string {
	if idx := strings.LastIndexByte(name, '.'); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// piiExfilFuncs are string/encoding/hashing/aggregation functions that could slice, encode,
// or transform a masked column to evade wire-level masking or leak raw bits.
var piiExfilFuncs = map[string]bool{
	"substring":          true,
	"substr":             true,
	"left":               true,
	"right":              true,
	"ascii":              true,
	"chr":                true,
	"length":             true,
	"char_length":        true,
	"character_length":   true,
	"octet_length":       true,
	"bit_length":         true,
	"md5":                true,
	"sha256":             true,
	"sha512":             true,
	"digest":             true,
	"encode":             true,
	"decode":             true,
	"convert_to":         true,
	"convert":            true,
	"to_hex":             true,
	"split_part":         true,
	"regexp_match":       true,
	"regexp_matches":     true,
	"regexp_replace":     true,
	"regexp_substr":      true,
	"regexp_count":       true,
	"regexp_instr":       true,
	"starts_with":        true,
	"reverse":            true,
	"concat":             true,
	"concat_ws":          true,
	"format":             true,
	"overlay":            true,
	"replace":            true,
	"position":           true,
	"strpos":             true,
	"translate":          true,
	"btrim":              true,
	"ltrim":              true,
	"rtrim":              true,
	"trim":               true,
	"upper":              true,
	"lower":              true,
	"initcap":            true,
	"lpad":               true,
	"rpad":               true,
	"repeat":             true,
	"quote_literal":      true,
	"quote_nullable":     true,
	"string_agg":         true,
	"array_agg":          true,
	"json_agg":           true,
	"jsonb_agg":          true,
	"to_json":            true,
	"to_jsonb":           true,
	"row_to_json":        true,
	"json_build_object":  true,
	"jsonb_build_object": true,
	"min":                true,
	"max":                true,
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

// detectPIIInference traverses the PostgreSQL 17 AST to catch side-channel oracle probes
// against masked PII columns in WHERE/HAVING/FILTER/WINDOW/DISTINCT/ORDER BY/GROUP BY/EXPLAIN clauses,
// projection operators (LIKE, >, ~, ||, IN, BETWEEN), risky casts (::bytea), and slicing/encoding functions.
func detectPIIInference(tree *pg_query.ParseResult, protected map[string]bool) (col string, via string) {
	var walkStmt func(n *pg_query.Node) (string, string)
	var findColInExpr func(n *pg_query.Node) string
	findColInExpr = func(n *pg_query.Node) string {
		if n == nil {
			return ""
		}
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
			if c := findColInExpr(inner.AExpr.Lexpr); c != "" {
				return c
			}
			return findColInExpr(inner.AExpr.Rexpr)
		case *pg_query.Node_BoolExpr:
			for _, a := range inner.BoolExpr.Args {
				if c := findColInExpr(a); c != "" {
					return c
				}
			}
		case *pg_query.Node_FuncCall:
			for _, a := range inner.FuncCall.Args {
				if c := findColInExpr(a); c != "" {
					return c
				}
			}
			if c := findColInExpr(inner.FuncCall.AggFilter); c != "" {
				return c
			}
			if inner.FuncCall.Over != nil {
				for _, p := range inner.FuncCall.Over.PartitionClause {
					if c := findColInExpr(p); c != "" {
						return c
					}
				}
				for _, o := range inner.FuncCall.Over.OrderClause {
					if c := findColInExpr(o); c != "" {
						return c
					}
				}
			}
		case *pg_query.Node_WindowDef:
			for _, p := range inner.WindowDef.PartitionClause {
				if c := findColInExpr(p); c != "" {
					return c
				}
			}
			for _, o := range inner.WindowDef.OrderClause {
				if c := findColInExpr(o); c != "" {
					return c
				}
			}
		case *pg_query.Node_TypeCast:
			return findColInExpr(inner.TypeCast.Arg)
		case *pg_query.Node_NullTest:
			return findColInExpr(inner.NullTest.Arg)
		case *pg_query.Node_BooleanTest:
			return findColInExpr(inner.BooleanTest.Arg)
		case *pg_query.Node_NamedArgExpr:
			return findColInExpr(inner.NamedArgExpr.Arg)
		case *pg_query.Node_CaseExpr:
			if c := findColInExpr(inner.CaseExpr.Arg); c != "" {
				return c
			}
			for _, w := range inner.CaseExpr.Args {
				if c := findColInExpr(w); c != "" {
					return c
				}
			}
			return findColInExpr(inner.CaseExpr.Defresult)
		case *pg_query.Node_CaseWhen:
			if c := findColInExpr(inner.CaseWhen.Expr); c != "" {
				return c
			}
			return findColInExpr(inner.CaseWhen.Result)
		case *pg_query.Node_CoalesceExpr:
			for _, a := range inner.CoalesceExpr.Args {
				if c := findColInExpr(a); c != "" {
					return c
				}
			}
		case *pg_query.Node_MinMaxExpr:
			for _, a := range inner.MinMaxExpr.Args {
				if c := findColInExpr(a); c != "" {
					return c
				}
			}
		case *pg_query.Node_RowExpr:
			for _, a := range inner.RowExpr.Args {
				if c := findColInExpr(a); c != "" {
					return c
				}
			}
		case *pg_query.Node_AArrayExpr:
			for _, el := range inner.AArrayExpr.Elements {
				if c := findColInExpr(el); c != "" {
					return c
				}
			}
		case *pg_query.Node_AIndirection:
			if c := findColInExpr(inner.AIndirection.Arg); c != "" {
				return c
			}
			for _, ind := range inner.AIndirection.Indirection {
				if c := findColInExpr(ind); c != "" {
					return c
				}
			}
		case *pg_query.Node_SubLink:
			if c := findColInExpr(inner.SubLink.Testexpr); c != "" {
				return c
			}
			return findColInExpr(inner.SubLink.Subselect)
		case *pg_query.Node_SelectStmt:
			if c, _ := walkStmt(n); c != "" {
				return c
			}
		case *pg_query.Node_List:
			for _, item := range inner.List.Items {
				if c := findColInExpr(item); c != "" {
					return c
				}
			}
		case *pg_query.Node_ResTarget:
			return findColInExpr(inner.ResTarget.Val)
		case *pg_query.Node_SortBy:
			return findColInExpr(inner.SortBy.Node)
		}
		return ""
	}

	var checkTargetsForTransform func(n *pg_query.Node) (string, string)
	checkTargetsForTransform = func(n *pg_query.Node) (string, string) {
		if n == nil {
			return "", ""
		}
		switch inner := n.Node.(type) {
		case *pg_query.Node_ResTarget:
			return checkTargetsForTransform(inner.ResTarget.Val)
		case *pg_query.Node_FuncCall:
			// Catch FILTER (WHERE tckn ...) and OVER (PARTITION/ORDER BY tckn)
			if c := findColInExpr(inner.FuncCall.AggFilter); c != "" {
				return c, "aggregate FILTER predicate"
			}
			if inner.FuncCall.Over != nil {
				for _, p := range inner.FuncCall.Over.PartitionClause {
					if c := findColInExpr(p); c != "" {
						return c, "WINDOW PARTITION BY clause"
					}
				}
				for _, o := range inner.FuncCall.Over.OrderClause {
					if c := findColInExpr(o); c != "" {
						return c, "WINDOW ORDER BY clause"
					}
				}
			}
			if len(inner.FuncCall.Funcname) > 0 {
				last := inner.FuncCall.Funcname[len(inner.FuncCall.Funcname)-1]
				if s := last.GetString_(); s != nil {
					fn := strings.ToLower(s.Sval)
					if piiExfilFuncs[fn] {
						for _, arg := range inner.FuncCall.Args {
							if c := findColInExpr(arg); c != "" {
								return c, fmt.Sprintf("expression function %s()", fn)
							}
						}
					}
				}
			}
			for _, arg := range inner.FuncCall.Args {
				if c, v := checkTargetsForTransform(arg); c != "" {
					return c, v
				}
			}
		case *pg_query.Node_AExpr:
			// Catch ANY operator/comparison/LIKE/ILIKE/IN/BETWEEN/SIMILAR/concat on a protected column in projection
			if c := findColInExpr(n); c != "" {
				opLabel := inner.AExpr.Kind.String()
				if len(inner.AExpr.Name) > 0 {
					if s := inner.AExpr.Name[len(inner.AExpr.Name)-1].GetString_(); s != nil {
						opLabel = s.Sval
					}
				}
				return c, fmt.Sprintf("projection operator %q", opLabel)
			}
		case *pg_query.Node_CaseExpr:
			if c := findColInExpr(n); c != "" {
				return c, "CASE projection"
			}
		case *pg_query.Node_CoalesceExpr:
			if c := findColInExpr(n); c != "" {
				return c, "COALESCE projection"
			}
		case *pg_query.Node_MinMaxExpr:
			if c := findColInExpr(n); c != "" {
				return c, "GREATEST/LEAST projection"
			}
		case *pg_query.Node_TypeCast:
			if isRiskyCast(inner.TypeCast) {
				if c := findColInExpr(inner.TypeCast.Arg); c != "" {
					return c, "binary/numeric type cast"
				}
			}
			return checkTargetsForTransform(inner.TypeCast.Arg)
		case *pg_query.Node_NamedArgExpr:
			return checkTargetsForTransform(inner.NamedArgExpr.Arg)
		case *pg_query.Node_RowExpr:
			for _, a := range inner.RowExpr.Args {
				if c, v := checkTargetsForTransform(a); c != "" {
					return c, v
				}
			}
		case *pg_query.Node_AArrayExpr:
			for _, el := range inner.AArrayExpr.Elements {
				if c, v := checkTargetsForTransform(el); c != "" {
					return c, v
				}
			}
		case *pg_query.Node_SubLink:
			return walkStmt(inner.SubLink.Subselect)
		}
		return "", ""
	}

	walkStmt = func(n *pg_query.Node) (string, string) {
		if n == nil {
			return "", ""
		}
		switch inner := n.Node.(type) {
		case *pg_query.Node_SelectStmt:
			s := inner.SelectStmt
			if s.WithClause != nil {
				for _, cte := range s.WithClause.Ctes {
					if cteNode := cte.GetCommonTableExpr(); cteNode != nil {
						if c, v := walkStmt(cteNode.Ctequery); c != "" {
							return c, v
						}
					}
				}
			}
			for _, dc := range s.DistinctClause {
				if c := findColInExpr(dc); c != "" {
					return c, "DISTINCT ON clause"
				}
			}
			if c := findColInExpr(s.WhereClause); c != "" {
				return c, "WHERE predicate"
			}
			if c := findColInExpr(s.HavingClause); c != "" {
				return c, "HAVING predicate"
			}
			for _, w := range s.WindowClause {
				if c := findColInExpr(w); c != "" {
					return c, "WINDOW clause"
				}
			}
			for _, sb := range s.SortClause {
				if c := findColInExpr(sb); c != "" {
					return c, "ORDER BY clause"
				}
			}
			for _, gb := range s.GroupClause {
				if c := findColInExpr(gb); c != "" {
					return c, "GROUP BY clause"
				}
			}
			for _, tl := range s.TargetList {
				if c, v := checkTargetsForTransform(tl); c != "" {
					return c, v
				}
			}
			for _, fc := range s.FromClause {
				if c, v := walkStmt(fc); c != "" {
					return c, v
				}
			}
			if s.Larg != nil {
				if c, v := walkStmt(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Larg}}); c != "" {
					return c, v
				}
			}
			if s.Rarg != nil {
				if c, v := walkStmt(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: s.Rarg}}); c != "" {
					return c, v
				}
			}
		case *pg_query.Node_ExplainStmt:
			return walkStmt(inner.ExplainStmt.Query)
		case *pg_query.Node_PrepareStmt:
			return walkStmt(inner.PrepareStmt.Query)
		case *pg_query.Node_DeclareCursorStmt:
			return walkStmt(inner.DeclareCursorStmt.Query)
		case *pg_query.Node_UpdateStmt:
			if c := findColInExpr(inner.UpdateStmt.WhereClause); c != "" {
				return c, "UPDATE WHERE predicate"
			}
		case *pg_query.Node_DeleteStmt:
			if c := findColInExpr(inner.DeleteStmt.WhereClause); c != "" {
				return c, "DELETE WHERE predicate"
			}
		case *pg_query.Node_InsertStmt:
			return walkStmt(inner.InsertStmt.SelectStmt)
		case *pg_query.Node_MergeStmt:
			if c := findColInExpr(inner.MergeStmt.JoinCondition); c != "" {
				return c, "MERGE ON predicate"
			}
		case *pg_query.Node_RangeSubselect:
			return walkStmt(inner.RangeSubselect.Subquery)
		case *pg_query.Node_JoinExpr:
			if c := findColInExpr(inner.JoinExpr.Quals); c != "" {
				return c, "JOIN predicate"
			}
			if c, v := walkStmt(inner.JoinExpr.Larg); c != "" {
				return c, v
			}
			return walkStmt(inner.JoinExpr.Rarg)
		}
		return "", ""
	}

	for _, raw := range tree.Stmts {
		if raw != nil && raw.Stmt != nil {
			if c, v := walkStmt(raw.Stmt); c != "" {
				return c, v
			}
		}
	}
	return "", ""
}

// extractTargetProvenance inspects the top-level SELECT / RETURNING target list so that
// column aliases (e.g. `SELECT full_name AS fn FROM customers`) still inherit explicit column_rules.
func extractTargetProvenance(tree *pg_query.ParseResult) ([][]string, map[string][]string) {
	if tree == nil || len(tree.Stmts) == 0 || tree.Stmts[0] == nil || tree.Stmts[0].Stmt == nil {
		return nil, nil
	}
	var targets []*pg_query.Node
	switch s := tree.Stmts[0].Stmt.Node.(type) {
	case *pg_query.Node_SelectStmt:
		targets = s.SelectStmt.TargetList
	case *pg_query.Node_InsertStmt:
		targets = s.InsertStmt.ReturningList
	case *pg_query.Node_UpdateStmt:
		targets = s.UpdateStmt.ReturningList
	case *pg_query.Node_DeleteStmt:
		targets = s.DeleteStmt.ReturningList
	default:
		return nil, nil
	}
	if len(targets) == 0 {
		return nil, nil
	}

	// If query uses SELECT *, positional mapping cannot predict expanded columns.
	hasStar := false
	positional := make([][]string, len(targets))
	aliases := make(map[string][]string)

	var collectCols func(n *pg_query.Node, out *[]string)
	collectCols = func(n *pg_query.Node, out *[]string) {
		if n == nil {
			return
		}
		switch inner := n.Node.(type) {
		case *pg_query.Node_ColumnRef:
			for _, f := range inner.ColumnRef.Fields {
				if f.GetAStar() != nil {
					hasStar = true
					return
				}
			}
			if len(inner.ColumnRef.Fields) > 0 {
				last := inner.ColumnRef.Fields[len(inner.ColumnRef.Fields)-1]
				if s := last.GetString_(); s != nil {
					*out = append(*out, strings.ToLower(s.Sval))
				}
			}
		case *pg_query.Node_TypeCast:
			collectCols(inner.TypeCast.Arg, out)
		case *pg_query.Node_FuncCall:
			for _, a := range inner.FuncCall.Args {
				collectCols(a, out)
			}
		case *pg_query.Node_CoalesceExpr:
			for _, a := range inner.CoalesceExpr.Args {
				collectCols(a, out)
			}
		case *pg_query.Node_AExpr:
			collectCols(inner.AExpr.Lexpr, out)
			collectCols(inner.AExpr.Rexpr, out)
		case *pg_query.Node_CaseExpr:
			collectCols(inner.CaseExpr.Arg, out)
			for _, w := range inner.CaseExpr.Args {
				collectCols(w, out)
			}
			collectCols(inner.CaseExpr.Defresult, out)
		case *pg_query.Node_CaseWhen:
			collectCols(inner.CaseWhen.Expr, out)
			collectCols(inner.CaseWhen.Result, out)
		}
	}

	for i, t := range targets {
		rt := t.GetResTarget()
		if rt == nil {
			continue
		}
		var cols []string
		collectCols(rt.Val, &cols)
		positional[i] = cols
		if rt.Name != "" && len(cols) > 0 {
			aliases[strings.ToLower(rt.Name)] = cols
		}
	}
	if hasStar {
		return nil, aliases
	}
	return positional, aliases
}
