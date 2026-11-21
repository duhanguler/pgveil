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

	// MaxSQLBytes caps raw SQL statement size before C libpg_query parsing to prevent memory/CPU DoS.
	MaxSQLBytes = 1024 * 1024 // 1 MiB
	// maxASTDepth bounds recursive AST traversal against deeply nested adversarial SQL payloads.
	maxASTDepth = 128
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
	TargetSources [][]string          `json:"-"` // Positional source column provenance per SELECT target (prevents alias/UNION masking bypasses)
	AliasSources  map[string][]string `json:"-"` // Lowercased output alias -> referenced source columns
}

// dangerousFunctions are PostgreSQL server-side functions that enable filesystem read/write,
// OS command execution, SSRF/lateral movement, denied-table bypasses, privilege escalation,
// secret GUC reads, sequence sabotage, lock exhaustion, or resource DoS.
var dangerousFunctions = map[string]bool{
	// Server filesystem & log directory access
	"pg_read_file":            true,
	"pg_read_binary_file":     true,
	"pg_ls_dir":               true,
	"pg_ls_logdir":            true,
	"pg_ls_waldir":            true,
	"pg_ls_tmpdir":            true,
	"pg_ls_archive_statusdir": true,
	"pg_ls_logicalmapdir":     true,
	"pg_ls_logicalsnapdir":    true,
	"pg_ls_replslotdir":       true,
	"pg_stat_file":            true,
	"pg_tablespace_location":  true,
	"pg_relation_filepath":    true,
	"pg_filenode_relation":    true,
	"pg_execute_server_program": true,

	// Large Object filesystem/data smuggling
	"lo_import":      true,
	"lo_export":      true,
	"lo_from_bytea":  true,
	"lo_put":         true,
	"lo_get":         true,
	"lo_open":        true,
	"lo_create":      true,
	"lo_unlink":      true,
	"lo_close":       true,
	"lo_lseek":       true,
	"lo_lseek64":     true,
	"lo_tell":        true,
	"lo_tell64":      true,
	"lo_truncate":    true,
	"lo_truncate64":  true,
	"loread":         true,
	"lowrite":        true,

	// SSRF & lateral database movement
	"dblink":           true,
	"dblink_exec":      true,
	"dblink_connect":   true,
	"dblink_connect_u": true,
	"dblink_open":      true,
	"dblink_fetch":     true,
	"dblink_send_query": true,

	// Dynamic SQL / denied-table bypasses via XML export & XXE/XPath
	"query_to_xml":                true,
	"query_to_xmlschema":          true,
	"query_to_xml_and_xmlschema":  true,
	"table_to_xml":                true,
	"table_to_xmlschema":          true,
	"table_to_xml_and_xmlschema":  true,
	"schema_to_xml":               true,
	"schema_to_xmlschema":         true,
	"schema_to_xml_and_xmlschema": true,
	"database_to_xml":             true,
	"database_to_xmlschema":       true,
	"database_to_xml_and_xmlschema": true,
	"cursor_to_xml":               true,
	"cursor_to_xmlschema":         true,
	"xmlparse":                    true,
	"xpath":                       true,
	"xpath_exists":                true,

	// Session config mutation / GUC secret disclosure / SELECT-embedded side effects
	"set_config":      true,
	"current_setting": true,
	"setval":          true,
	"pg_notify":       true,

	// Cluster control, replication slots, WAL, backup & backend termination
	"pg_terminate_backend":               true,
	"pg_cancel_backend":                  true,
	"pg_reload_conf":                     true,
	"pg_rotate_logfile":                  true,
	"pg_switch_wal":                      true,
	"pg_export_snapshot":                 true,
	"pg_promote":                         true,
	"pg_backup_start":                    true,
	"pg_backup_stop":                     true,
	"pg_start_backup":                    true,
	"pg_stop_backup":                     true,
	"pg_create_restore_point":            true,
	"pg_create_physical_replication_slot": true,
	"pg_create_logical_replication_slot": true,
	"pg_drop_replication_slot":           true,
	"pg_copy_physical_replication_slot":  true,
	"pg_copy_logical_replication_slot":   true,
	"pg_sync_replication_slots":          true,
	"pg_replication_origin_create":       true,
	"pg_replication_origin_drop":         true,
	"pg_replication_origin_advance":      true,
	"pg_logical_emit_message":            true,
	"pg_logical_slot_get_changes":        true,
	"pg_logical_slot_peek_changes":       true,
	"pg_logical_slot_get_binary_changes": true,
	"pg_log_standby_snapshot":            true,
	"pg_log_backend_memory_contexts":     true,
	"pg_stat_reset":                      true,
	"pg_stat_reset_shared":               true,
	"pg_import_system_collations":        true,

	// Sleep & advisory lock exhaustion DoS
	"pg_sleep":                    true,
	"pg_sleep_for":                true,
	"pg_sleep_until":              true,
	"pg_advisory_lock":            true,
	"pg_advisory_lock_shared":     true,
	"pg_advisory_xact_lock":       true,
	"pg_advisory_xact_lock_shared": true,
	"pg_wait_for_backend_termination": true,
}

// sensitiveSystemTables contain credential hashes, foreign/replication passwords,
// raw planner PII samples (pg_stats), large objects, live cross-session SQL queries,
// or sensitive server internals.
var sensitiveSystemTables = map[string]bool{
	"pg_shadow":                 true,
	"pg_authid":                 true,
	"pg_auth_members":           true,
	"pg_roles":                  true,
	"pg_user":                   true,
	"pg_group":                  true,
	"pg_user_mappings":          true, // Cleartext FDW foreign server credentials
	"pg_user_mapping":           true,
	"pg_foreign_server":         true,
	"pg_subscription":           true, // Logical replication conninfo credentials
	"pg_stat_wal_receiver":      true, // Primary replication conninfo
	"pg_stat_replication":       true,
	"pg_replication_slots":      true,
	"pg_largeobject":            true, // Raw imported files / binary secrets
	"pg_largeobject_metadata":   true,
	"pg_file_settings":          true,
	"pg_hba_file_rules":         true,
	"pg_ident_file_mappings":    true,
	"pg_stats":                  true, // Planner most_common_vals / histogram_bounds raw PII!
	"pg_stats_ext":              true,
	"pg_stats_ext_exprs":        true,
	"pg_statistic":              true,
	"pg_statistic_ext_data":     true,
	"pg_stat_activity":          true, // Live cross-session SQL & literals
	"pg_stat_statements":        true,
	"pg_stat_ssl":               true,
	"pg_settings":               true,
	"pg_config":                 true,
	"pg_prepared_statements":    true,
	"pg_cursors":                true,
	"pg_shmem_allocations":      true,
	"pg_backend_memory_contexts": true,
}

// safeHousekeeping are non-data session commands sent automatically by drivers (pgx, psql, psycopg).
var safeHousekeeping = map[string]bool{
	"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "SAVEPOINT": true,
	"RELEASE": true, "DEALLOCATE": true, "DISCARD": true, "CLOSE": true,
	"UNLISTEN": true,
}

// Evaluate parses sql using PostgreSQL 17's own C AST parser (libpg_query) and enforces the role's FirewallPolicy.
func Evaluate(sql string, profile *policy.RoleProfile) Decision {
	// 0a. Reject embedded NUL bytes to prevent Go-string vs C-string truncation discrepancies in libpg_query
	if strings.IndexByte(sql, 0) >= 0 {
		return Decision{
			Action:        ActionBlock,
			StatementType: "INVALID_NUL",
			RiskLevel:     "CRITICAL",
			Rule:          "invalid_nul_byte",
			Reason:        "SQL containing embedded NUL byte is rejected to prevent C-parser truncation mismatch",
			Fingerprint:   "invalid_nul",
		}
	}

	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || trimmed == ";" {
		return Decision{
			Action:        ActionAllow,
			StatementType: "EMPTY",
			RiskLevel:     "LOW",
			Rule:          "empty_query",
		}
	}

	// 0b. SQL payload size cap against parser DoS
	if len(trimmed) > MaxSQLBytes {
		return Decision{
			Action:        ActionBlock,
			StatementType: "OVERSIZED_SQL",
			RiskLevel:     "HIGH",
			Rule:          "sql_size_limit",
			Reason:        fmt.Sprintf("SQL payload (%d bytes) exceeds maximum allowed size (%d bytes)", len(trimmed), MaxSQLBytes),
			Fingerprint:   "oversized_sql",
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

	// Parse with real PostgreSQL 17 C parser
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
	if analysis.depthExceeded {
		return Decision{
			Action:        ActionBlock,
			StatementType: analysis.primaryType,
			RiskLevel:     "HIGH",
			Rule:          "ast_complexity_limit",
			Reason:        fmt.Sprintf("SQL AST nesting depth exceeded safety limit (%d levels)", maxASTDepth),
			Fingerprint:   fp,
		}
	}

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

	// 2. Dangerous server functions, COPY TO/FROM PROGRAM, DO blocks, privilege escalation
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
			dec.Reason = "COPY TO/FROM PROGRAM, server filesystem access, or dynamic library LOAD is blocked"
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
			dec.Reason = "SET ROLE / SESSION AUTHORIZATION / row_security / RESET ALL privilege escalation is blocked"
			return dec
		}
	}

	// 2b. Prevent COPY TO STDOUT from bypassing DataRow PII masking or row exfiltration caps
	if analysis.hasCopyOut && (profile.Masking.Enabled || fw.MaxRows > 0) {
		dec.Action = ActionBlock
		dec.RiskLevel = "CRITICAL"
		dec.Rule = "block_copy_exfiltration"
		dec.Reason = "COPY TO STDOUT is blocked for masked or row-capped profiles because CopyData streams bypass DataRow masking"
		return dec
	}

	// 3. Fail-Closed DDL Blocking (includes RENAME, OWNER, DROP OWNED, FDW, SUBSCRIPTION, SELECT INTO, unknown DDL)
	if fw.BlockDDL && analysis.isDDL {
		dec.Action = ActionBlock
		dec.RiskLevel = "CRITICAL"
		dec.Rule = "block_ddl"
		dec.Reason = fmt.Sprintf("DDL / administrative statement (%s) is blocked for profile %q", analysis.primaryType, profile.Name)
		return dec
	}

	// 4. Write without WHERE or tautological WHERE (1=1, 2>1, 1+1=2, id=id, EXISTS(SELECT 1), MERGE ON 1=1)
	if fw.BlockWriteWithoutWhere && analysis.writeWithoutWhere {
		dec.Action = ActionBlock
		dec.RiskLevel = "CRITICAL"
		dec.Rule = "block_write_without_where"
		dec.Reason = fmt.Sprintf("Unscoped %s without effective WHERE/ON predicate (or tautology) is blocked", analysis.primaryType)
		return dec
	}

	// 5. Table Denylist, System Catalog / pg_toast Lockout & Table Allowlist
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
		if fw.BlockSystemCatalogs && isSensitiveCatalog(lt, bare) {
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

	// 6. AST Taint-Tracking PII Side-Channel Oracle & Whole-Row Exfiltration Guard
	if fw.BlockPIIInference {
		protected := resolveProtectedColumns(profile)
		if len(protected) > 0 {
			if col, rule, via := detectPIIInference(tree, protected); col != "" {
				dec.Action = ActionBlock
				dec.RiskLevel = "HIGH"
				dec.Rule = rule
				dec.Reason = fmt.Sprintf("PII side-channel inference blocked: protected target %q referenced in %s", col, via)
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

	// 8. Human-in-the-Loop (HITL) Approval Trigger (checks primary statement AND modifying CTEs)
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

	// 9. Statement Allowlist (safe driver transaction housekeeping permitted)
	if !containsWildcard(fw.AllowStatements) {
		allowSet := toUpperSet(fw.AllowStatements)
		for _, st := range analysis.allTypes {
			if allowSet[st] || safeHousekeeping[st] {
				continue
			}
			// Allow benign SET client_encoding / application_name / timezone from drivers
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

func isSensitiveCatalog(fullLower, bareLower string) bool {
	if sensitiveSystemTables[bareLower] {
		return true
	}
	if strings.HasPrefix(fullLower, "pg_toast.") || strings.HasPrefix(bareLower, "pg_toast_") {
		return true
	}
	if strings.HasPrefix(fullLower, "pg_catalog.pg_auth") ||
		strings.HasPrefix(fullLower, "pg_catalog.pg_shadow") ||
		strings.HasPrefix(fullLower, "pg_catalog.pg_stat") ||
		strings.HasPrefix(fullLower, "pg_catalog.pg_largeobject") ||
		strings.HasPrefix(fullLower, "pg_catalog.pg_user_mapping") ||
		strings.HasPrefix(fullLower, "pg_catalog.pg_subscription") {
		return true
	}
	return false
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
