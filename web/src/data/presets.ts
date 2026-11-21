export interface QueryPreset {
  id: string
  label: string
  shortLabel: string
  category: 'masking' | 'firewall' | 'hitl'
  sql: string
  hint: string
}

export const QUERY_PRESETS: QueryPreset[] = [
  {
    id: 'customers_pii',
    label: 'Customers PII (KVKK + GDPR Wire Mask)',
    shortLabel: 'Customers PII',
    category: 'masking',
    sql: 'SELECT id, full_name, email, phone, tckn, iban, city\nFROM customers\nORDER BY id\nLIMIT 8;',
    hint: 'Dynamic wire-speed masking on TCKN, IBAN, email, phone, and JOIN-preserving hashed names.'
  },
  {
    id: 'tickets_secrets',
    label: 'Support Tickets (Free-Text Secrets & PII)',
    shortLabel: 'Tickets Secrets',
    category: 'masking',
    sql: 'SELECT id, subject, body, priority\nFROM support_tickets\nORDER BY id;',
    hint: 'Scans unstructured text cells for embedded TCKNs, IBANs, Luhn credit cards, SSNs, and AWS keys.'
  },
  {
    id: 'bulk_exfil',
    label: 'Bulk Exfiltration (40 Rows → Cap 25)',
    shortLabel: 'Bulk Cap',
    category: 'masking',
    sql: 'SELECT id, full_name, email, tckn, city\nFROM customers;',
    hint: 'Enforces ai_agent 25-row exfiltration cap with wire truncation and PostgreSQL NOTICE.'
  },
  {
    id: 'pii_oracle_like',
    label: 'PII Side-Channel (WHERE tckn LIKE)',
    shortLabel: 'Oracle WHERE',
    category: 'firewall',
    sql: "SELECT id, full_name\nFROM customers\nWHERE tckn LIKE '100000%';",
    hint: 'AST side-channel oracle guard blocks brute-force inference probes against masked columns.'
  },
  {
    id: 'pii_oracle_substr',
    label: 'Projection Bypass (SUBSTRING iban)',
    shortLabel: 'SUBSTRING Bypass',
    category: 'firewall',
    sql: 'SELECT id, SUBSTRING(iban, 1, 10) AS prefix\nFROM customers;',
    hint: 'Blocks string slicing / aliasing evasion attempts on protected PII columns.'
  },
  {
    id: 'hitl_update',
    label: 'Live HITL Hold (Scoped UPDATE)',
    shortLabel: 'HITL UPDATE',
    category: 'hitl',
    sql: "UPDATE orders\nSET status = 'refunded'\nWHERE id = 1001;",
    hint: 'Pauses the live PostgreSQL TCP connection until an operator approves or denies.'
  },
  {
    id: 'drop_table',
    label: 'DDL Attack (DROP TABLE)',
    shortLabel: 'DROP TABLE',
    category: 'firewall',
    sql: 'DROP TABLE orders;',
    hint: 'PostgreSQL 17 AST firewall rejects DDL before reaching upstream Postgres.'
  },
  {
    id: 'tautology_delete',
    label: 'Tautology Wipe (WHERE 1 = 1)',
    shortLabel: 'WHERE 1=1',
    category: 'firewall',
    sql: 'DELETE FROM orders WHERE 1 = 1;',
    hint: 'AST predicate analyzer catches always-true tautologies that evade regex filters.'
  },
  {
    id: 'pg_read_file',
    label: 'Server Escape (pg_read_file)',
    shortLabel: 'pg_read_file',
    category: 'firewall',
    sql: "SELECT pg_read_file('/etc/passwd');",
    hint: 'Blocks dangerous server filesystem/RCE functions (pg_read_file, COPY TO PROGRAM, DO $$).'
  },
  {
    id: 'denied_secrets',
    label: 'Restricted Table (api_secrets)',
    shortLabel: 'api_secrets',
    category: 'firewall',
    sql: 'SELECT service_name, secret_value\nFROM api_secrets;',
    hint: 'Enforces table denylist even inside subqueries and CTEs.'
  },
  {
    id: 'cte_taint_leak',
    label: 'CTE Taint Alias Bypass (WITH leak)',
    shortLabel: 'CTE Taint',
    category: 'firewall',
    sql: "WITH leak AS (\n  SELECT id, tckn AS innocent FROM customers\n)\nSELECT id FROM leak WHERE innocent LIKE '100000%';",
    hint: 'AST fixed-point taint propagation tracks aliased PII columns across multi-hop CTEs and subqueries.'
  },
  {
    id: 'whole_row_exfil',
    label: 'Whole-Row Serialization (c::text)',
    shortLabel: 'Whole-Row Exfil',
    category: 'firewall',
    sql: 'SELECT c::text\nFROM customers c\nLIMIT 5;',
    hint: 'Blocks whole-row composite projection/serialization (c::text, row_to_json(c)) that bypasses column masking.'
  },
  {
    id: 'positional_order_oracle',
    label: 'Positional Oracle (ORDER BY 2)',
    shortLabel: 'ORDER BY 2',
    category: 'firewall',
    sql: 'SELECT id, tckn\nFROM customers\nORDER BY 2;',
    hint: 'Blocks binary-search positional ORDER BY / GROUP BY index probes against protected PII columns.'
  }
]
