export interface FirewallDecision {
  action: 'ALLOW' | 'BLOCK' | 'REQUIRE_HITL'
  statement_type: string
  risk_level: string
  reason: string
  rule: string
  tables?: string[]
  fingerprint: string
  has_select_star?: boolean
}

export interface AuditEvent {
  event_id: string
  trace_id?: string
  occurred_at: string
  client_addr: string
  db_user: string
  database_name: string
  application_name?: string
  role_profile: string
  statement_type: string
  sql_fingerprint: string
  raw_sql_preview: string
  rls_rewritten?: boolean
  rls_rules_applied?: string[]
  rewritten_sql_preview?: string
  decision: string
  risk_level: string
  policy_rule: string
  policy_reason?: string
  tables_accessed?: string[]
  rows_returned: number
  rows_truncated: boolean
  pii_fields_masked: number
  pii_entities?: Record<string, number>
  proxy_overhead_us: number
  upstream_duration_us: number
}

export interface Summary {
  total_queries: number
  masked_queries: number
  blocked_queries: number
  truncated_queries: number
  hitl_triggered: number
  total_pii_fields: number
  total_rows_returned: number
  avg_proxy_overhead_us: number
  kafka_enabled: boolean
  by_decision: Record<string, number>
  by_role: Record<string, number>
  pii_by_entity: Record<string, number>
  blocked_by_rule: Record<string, number>
}

export interface ApprovalRequest {
  id: string
  created_at: string
  expires_at: string
  resolved_at?: string
  client_addr: string
  db_user: string
  database: string
  application_name?: string
  role_profile: string
  statement_type: string
  risk_level: string
  rule: string
  reason: string
  tables?: string[]
  sql: string
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED'
  reviewer?: string
  reviewer_note?: string
}

export interface RoleProfile {
  name: string
  description: string
  mode?: string
  match: {
    application_names?: string[]
    users?: string[]
  }
  firewall: {
    allow_statements?: string[]
    block_ddl: boolean
    block_multi_statement: boolean
    block_write_without_where: boolean
    block_dangerous_functions: boolean
    block_system_catalogs: boolean
    block_pii_inference?: boolean
    protected_columns?: string[]
    require_hitl_statements?: string[]
    hitl_mode: string
    hitl_timeout: string
    denied_tables?: string[]
    row_filters?: { table: string; predicate: string }[]
    max_rows: number
    max_rows_action: string
    rate_limit?: {
      max_queries_per_minute: number
      loop_threshold: number
      loop_window: string
    }
  }
  masking: {
    enabled: boolean
    auto_detect_pii: boolean
    compliance_packs?: string[]
    column_rules?: { column: string; strategy: string }[]
  }
}

export interface PlaygroundResult {
  status: 'ok' | 'blocked' | 'connection_error'
  profile: string
  decision?: FirewallDecision
  columns?: string[]
  rows?: (string | null)[][]
  row_count?: number
  command_tag?: string
  notices?: string[]
  duration_ms?: number
  error?: string
  sqlstate?: string
  detail?: string
  audit?: AuditEvent
}

export interface DiscoveryFinding {
  schema: string
  table: string
  column: string
  data_type: string
  sampled_rows: number
  matched_rows: number
  detected_entities: Record<string, number>
  compliance_packs: string[]
  risk_level: string
  recommended_strategy: string
  detection_source: string
  sample_masked?: string
}

export interface DiscoveryReport {
  scanned_at: string
  database: string
  tables_scanned: number
  columns_scanned: number
  findings_count: number
  findings: DiscoveryFinding[]
  recommended_denied_tables?: string[]
  generated_yaml: string
}
