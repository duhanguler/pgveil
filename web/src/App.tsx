import React, { useEffect, useState, useCallback, useRef } from 'react'
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Activity,
  Clock,
  Sliders,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Database,
  Lock,
  EyeOff,
  Cpu,
  Radio,
  RefreshCw,
  Copy,
  Check,
  Layers,
  ScanSearch
} from 'lucide-react'
import type {
  ApprovalRequest,
  AuditEvent,
  DiscoveryReport,
  PlaygroundResult,
  RoleProfile,
  Summary
} from './types'

type Tab = 'playground' | 'discovery' | 'approvals' | 'audit' | 'policies' | 'observability'

interface Preset {
  label: string
  badge: string
  tone: 'emerald' | 'amber' | 'rose' | 'cyan'
  sql: string
  description: string
}

const PRESETS: Preset[] = [
  {
    label: 'Customer PII (KVKK + GDPR)',
    badge: 'WIRE MASK',
    tone: 'emerald',
    sql: 'SELECT id, full_name, email, phone, tckn, iban, city\nFROM customers\nORDER BY id\nLIMIT 8;',
    description: 'Dynamic wire-speed masking on TCKN, IBAN, phone, email, and deterministic pseudonymized names.'
  },
  {
    label: 'Unstructured Tickets (Auto-PII + Secrets)',
    badge: 'AUTO DETECT',
    tone: 'cyan',
    sql: 'SELECT id, subject, body, priority\nFROM support_tickets\nORDER BY id;',
    description: 'Auto-scans free-text columns for embedded TCKNs, IBANs, Luhn credit cards, SSNs, and AWS keys.'
  },
  {
    label: 'Bulk Exfiltration (40 Rows)',
    badge: 'ROW CAP',
    tone: 'amber',
    sql: 'SELECT id, full_name, email, tckn, city\nFROM customers;',
    description: 'Tests the ai_agent 25-row exfiltration ceiling with wire-level truncation & PostgreSQL NOTICE.'
  },
  {
    label: 'Live HITL Hold (Scoped UPDATE)',
    badge: 'HITL HOLD',
    tone: 'amber',
    sql: "UPDATE orders\nSET status = 'refunded'\nWHERE id = 1001;",
    description: 'Pauses the live PostgreSQL connection until a human operator clicks Approve or Deny.'
  },
  {
    label: 'PII Side-Channel (WHERE tckn LIKE)',
    badge: 'ORACLE GUARD',
    tone: 'rose',
    sql: "SELECT id, full_name FROM customers\nWHERE tckn LIKE '100000%';",
    description: 'AST side-channel guard blocks brute-force inference probes against masked PII columns.'
  },
  {
    label: 'SUBSTRING Alias Bypass (iban)',
    badge: 'ORACLE GUARD',
    tone: 'rose',
    sql: 'SELECT id, SUBSTRING(iban, 1, 10) AS prefix\nFROM customers;',
    description: 'Stops AI agents from slicing or aliasing protected PII columns to evade wire masking.'
  },
  {
    label: 'DROP TABLE Attack',
    badge: 'AST BLOCK',
    tone: 'rose',
    sql: 'DROP TABLE orders;',
    description: 'PostgreSQL 17 AST firewall blocks DDL before a single byte reaches upstream Postgres.'
  },
  {
    label: 'Tautology Wipe (WHERE 1=1)',
    badge: 'AST BLOCK',
    tone: 'rose',
    sql: 'DELETE FROM orders WHERE 1 = 1;',
    description: 'AST predicate analyzer catches always-true tautologies that evade regex firewalls.'
  },
  {
    label: 'Server Escape (pg_read_file)',
    badge: 'AST BLOCK',
    tone: 'rose',
    sql: "SELECT pg_read_file('/etc/passwd');",
    description: 'Blocks dangerous server-side filesystem/RCE functions (pg_read_file, COPY TO PROGRAM, DO $$).'
  },
  {
    label: 'Restricted Table (api_secrets)',
    badge: 'DENIED TABLE',
    tone: 'rose',
    sql: 'SELECT service_name, secret_value FROM api_secrets;',
    description: 'Blocks access to restricted tables even when nested inside subqueries or CTEs.'
  }
]

function decisionBadge(decision: string) {
  switch (decision) {
    case 'MASKED':
      return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
    case 'ALLOW':
      return 'bg-sky-500/15 text-sky-300 border-sky-500/30'
    case 'TRUNCATED':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/30'
    case 'HITL_APPROVED':
      return 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30'
    case 'WOULD_BLOCK':
    case 'WOULD_HITL':
      return 'bg-purple-500/15 text-purple-300 border-purple-500/30'
    case 'BLOCKED':
    case 'HITL_DENIED':
    case 'HITL_EXPIRED':
      return 'bg-rose-500/15 text-rose-300 border-rose-500/30'
    default:
      return 'bg-slate-700/40 text-slate-300 border-slate-600/40'
  }
}

function isMaskedLook(val: string | null): boolean {
  if (!val) return false
  return (
    val.includes('***') ||
    val.includes('****') ||
    val.includes('[REDACTED') ||
    val.startsWith('tok_') ||
    val.startsWith('tckn_') ||
    val.startsWith('user_')
  )
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch {
    return iso
  }
}

export default function App() {
  const [tab, setTab] = useState<Tab>('playground')
  const [summary, setSummary] = useState<Summary | null>(null)
  const [proxyAddr, setProxyAddr] = useState(':6432')
  const [version, setVersion] = useState('0.1.0')
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [profiles, setProfiles] = useState<RoleProfile[]>([])
  const [compliancePacks, setCompliancePacks] = useState<Record<string, string[]>>({})
  const [policyYAML, setPolicyYAML] = useState('')
  const [policyVersion, setPolicyVersion] = useState(1)
  const [sseConnected, setSseConnected] = useState(false)

  // Playground state
  const [selectedProfile, setSelectedProfile] = useState('ai_agent')
  const [sql, setSql] = useState(PRESETS[0].sql)
  const [running, setRunning] = useState(false)
  const [pgResult, setPgResult] = useState<PlaygroundResult | null>(null)

  // Audit filters
  const [decisionFilter, setDecisionFilter] = useState('')
  const [roleFilter, setRoleFilter] = useState('')

  // Policy editor state
  const [savingPolicy, setSavingPolicy] = useState(false)
  const [policyNotice, setPolicyNotice] = useState<{ ok: boolean; msg: string } | null>(null)
  const [copiedSnippet, setCopiedSnippet] = useState<string | null>(null)

  // Schema PII Discovery state
  const [discovering, setDiscovering] = useState(false)
  const [discoveryReport, setDiscoveryReport] = useState<DiscoveryReport | null>(null)
  const [discoveryErr, setDiscoveryErr] = useState<string | null>(null)

  const runDiscovery = async () => {
    setDiscovering(true)
    setDiscoveryErr(null)
    try {
      const res = await fetch('/api/v1/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sample_rows: 50 })
      })
      const data = await res.json()
      if (!res.ok) {
        setDiscoveryErr(data.error || 'Discovery scan failed')
      } else {
        setDiscoveryReport(data)
      }
    } catch (err) {
      setDiscoveryErr(String(err))
    } finally {
      setDiscovering(false)
    }
  }

  const summaryTimerRef = useRef<number | null>(null)

  const fetchSummary = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/summary')
      if (!res.ok) return
      const data = await res.json()
      setSummary(data.summary)
      if (data.proxy_addr) setProxyAddr(data.proxy_addr)
      if (data.version) setVersion(data.version)
    } catch {
      // ignore transient network errors
    }
  }, [])

  const fetchInitialData = useCallback(async () => {
    await fetchSummary()
    try {
      const [evRes, apRes, polRes] = await Promise.all([
        fetch('/api/v1/events?limit=120'),
        fetch('/api/v1/approvals'),
        fetch('/api/v1/policies')
      ])
      if (evRes.ok) {
        const d = await evRes.json()
        setEvents(d.events || [])
      }
      if (apRes.ok) {
        const d = await apRes.json()
        setApprovals(d.approvals || [])
      }
      if (polRes.ok) {
        const d = await polRes.json()
        setProfiles(d.profiles || [])
        setCompliancePacks(d.compliance_packs || {})
        setPolicyYAML(d.yaml || '')
        setPolicyVersion(d.version || 1)
      }
    } catch {
      // ignore
    }
  }, [fetchSummary])

  useEffect(() => {
    fetchInitialData()
  }, [fetchInitialData])

  // Real-time Server-Sent Events (SSE) subscription for live audit events & HITL queue transitions
  useEffect(() => {
    const es = new EventSource('/api/v1/events/stream')
    es.onopen = () => setSseConnected(true)
    es.onerror = () => setSseConnected(false)

    es.addEventListener('audit', (e: MessageEvent) => {
      try {
        const ev: AuditEvent = JSON.parse(e.data)
        setEvents((prev) => [ev, ...prev].slice(0, 200))
        if (summaryTimerRef.current) window.clearTimeout(summaryTimerRef.current)
        summaryTimerRef.current = window.setTimeout(() => fetchSummary(), 120)
      } catch {
        // ignore
      }
    })

    es.addEventListener('approval', (e: MessageEvent) => {
      try {
        const req: ApprovalRequest = JSON.parse(e.data)
        setApprovals((prev) => {
          const idx = prev.findIndex((item) => item.id === req.id)
          if (idx >= 0) {
            const next = [...prev]
            next[idx] = req
            return next
          }
          return [req, ...prev]
        })
        fetchSummary()
      } catch {
        // ignore
      }
    })

    return () => {
      es.close()
      if (summaryTimerRef.current) window.clearTimeout(summaryTimerRef.current)
    }
  }, [fetchSummary])

  const pendingApprovals = approvals.filter((a) => a.status === 'PENDING')

  const runQuery = async () => {
    if (!sql.trim() || running) return
    setRunning(true)
    setPgResult(null)
    try {
      const res = await fetch('/api/v1/playground/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql, profile: selectedProfile })
      })
      const data: PlaygroundResult = await res.json()
      setPgResult(data)
    } catch (err) {
      setPgResult({
        status: 'connection_error',
        profile: selectedProfile,
        error: String(err)
      })
    } finally {
      setRunning(false)
      fetchSummary()
    }
  }

  const resolveApproval = async (id: string, approve: boolean, note?: string) => {
    try {
      await fetch(`/api/v1/approvals/${id}/${approve ? 'approve' : 'deny'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reviewer: 'console-operator',
          note: note || (approve ? 'Approved via pgveil Web Console' : 'Denied via pgveil Web Console')
        })
      })
    } catch {
      // ignore
    }
  }

  const savePolicyYAML = async () => {
    setSavingPolicy(true)
    setPolicyNotice(null)
    try {
      const res = await fetch('/api/v1/policies/yaml', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: policyYAML })
      })
      const data = await res.json()
      if (!res.ok) {
        setPolicyNotice({ ok: false, msg: data.error || 'Validation failed' })
      } else {
        setPolicyVersion(data.version)
        setPolicyNotice({ ok: true, msg: `Hot-reloaded policy version v${data.version} with zero downtime.` })
        fetchInitialData()
      }
    } catch (err) {
      setPolicyNotice({ ok: false, msg: String(err) })
    } finally {
      setSavingPolicy(false)
    }
  }

  const copyText = (key: string, text: string) => {
    navigator.clipboard?.writeText(text)
    setCopiedSnippet(key)
    setTimeout(() => setCopiedSnippet(null), 1500)
  }

  const activeProfileObj = profiles.find((p) => p.name === selectedProfile)
  const filteredEvents = events.filter((e) => {
    if (decisionFilter && e.decision !== decisionFilter) return false
    if (roleFilter && e.role_profile !== roleFilter) return false
    return true
  })

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-950/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
              <Shield className="w-5 h-5 text-slate-950 stroke-[2.4]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white">pgveil</span>
                <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-emerald-300 border border-slate-700">
                  v{version}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden xl:block whitespace-nowrap">
                PostgreSQL Wire Masking &amp; SQL Firewall
              </p>
            </div>
          </div>

          <nav className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800 shrink-0">
            {[
              { id: 'playground', label: 'SQL Playground', icon: Terminal },
              { id: 'discovery', label: 'PII Discovery', icon: ScanSearch },
              { id: 'approvals', label: 'HITL Approvals', icon: Clock, count: pendingApprovals.length },
              { id: 'audit', label: 'Audit Stream', icon: Activity },
              { id: 'policies', label: 'Policies', icon: Sliders },
              { id: 'observability', label: 'Telemetry', icon: Cpu }
            ].map((item) => {
              const Icon = item.icon
              const active = tab === item.id
              return (
                <button
                  key={item.id}
                  onClick={() => setTab(item.id as Tab)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition ${
                    active
                      ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5 shrink-0" />
                  <span className="hidden md:inline">{item.label}</span>
                  {item.count ? (
                    <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500 text-slate-950 animate-pulse">
                      {item.count}
                    </span>
                  ) : null}
                </button>
              )
            })}
          </nav>

          <div className="hidden lg:flex items-center gap-2 text-xs font-mono shrink-0">
            <span className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300 flex items-center gap-1.5 whitespace-nowrap">
              <Database className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              wire {proxyAddr.replace('[::]', '')}
            </span>
            <span
              className={`px-2.5 py-1 rounded-md border flex items-center gap-1.5 whitespace-nowrap ${
                sseConnected
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                  : 'bg-slate-900 border-slate-800 text-slate-400'
              }`}
            >
              <Radio className={`w-3 h-3 shrink-0 ${sseConnected ? 'animate-pulse text-emerald-400' : ''}`} />
              {sseConnected ? 'LIVE' : 'SYNC'}
            </span>
          </div>
        </div>
      </header>

      {/* KPI Strip */}
      <section className="border-b border-slate-800/70 bg-slate-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 grid grid-cols-2 sm:grid-cols-5 gap-3">
          <KpiCard
            label="Inspected Queries"
            value={(summary?.total_queries ?? 0).toLocaleString()}
            icon={<Database className="w-4 h-4 text-cyan-400" />}
          />
          <KpiCard
            label="PII Cells Masked"
            value={(summary?.total_pii_fields ?? 0).toLocaleString()}
            accent="text-emerald-400"
            icon={<EyeOff className="w-4 h-4 text-emerald-400" />}
          />
          <KpiCard
            label="Blocked Attacks"
            value={(summary?.blocked_queries ?? 0).toLocaleString()}
            accent="text-rose-400"
            icon={<ShieldAlert className="w-4 h-4 text-rose-400" />}
          />
          <KpiCard
            label="Pending HITL"
            value={pendingApprovals.length}
            accent={pendingApprovals.length > 0 ? 'text-amber-400' : 'text-slate-200'}
            icon={<Clock className="w-4 h-4 text-amber-400" />}
          />
          <KpiCard
            label="Avg Proxy Overhead"
            value={`${Math.round(summary?.avg_proxy_overhead_us ?? 0)} µs`}
            accent="text-indigo-300"
            icon={<Cpu className="w-4 h-4 text-indigo-400" />}
          />
        </div>
      </section>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {/* TAB 1: LIVE WIRE SQL PLAYGROUND */}
        {tab === 'playground' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left Sidebar: Profiles & Scenarios */}
            <div className="lg:col-span-4 space-y-5">
              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  Client Role Profile
                </h2>
                <div className="grid grid-cols-2 gap-2">
                  {(profiles.length
                    ? profiles
                    : [{ name: 'ai_agent' }, { name: 'analyst' }, { name: 'developer' }, { name: 'admin' }]
                  ).map((p) => (
                    <button
                      key={p.name}
                      onClick={() => setSelectedProfile(p.name)}
                      className={`px-3 py-2 rounded-lg text-left border transition ${
                        selectedProfile === p.name
                          ? 'bg-emerald-500/15 border-emerald-500/50 text-emerald-200'
                          : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                      }`}
                    >
                      <div className="font-mono text-xs font-semibold">{p.name}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5 truncate">
                        {'firewall' in p
                          ? p.firewall.max_rows > 0
                            ? `max ${p.firewall.max_rows} rows`
                            : 'unlimited'
                          : 'profile'}
                      </div>
                    </button>
                  ))}
                </div>

                {activeProfileObj && (
                  <div className="mt-3 pt-3 border-t border-slate-800 text-xs text-slate-400 space-y-2">
                    <p className="leading-relaxed">{activeProfileObj.description}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {(activeProfileObj.masking.compliance_packs || []).map((pack) => (
                        <span
                          key={pack}
                          className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 font-mono text-[10px] uppercase"
                        >
                          {pack}
                        </span>
                      ))}
                      {!activeProfileObj.masking.enabled && (
                        <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 font-mono text-[10px]">
                          UNMASKED BREAK-GLASS
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                  1-Click Attack & Masking Scenarios
                </h2>
                <div className="space-y-2">
                  {PRESETS.map((preset) => (
                    <button
                      key={preset.label}
                      onClick={() => setSql(preset.sql)}
                      className="w-full text-left p-2.5 rounded-lg bg-slate-950/70 hover:bg-slate-800/70 border border-slate-800/80 hover:border-slate-700 transition group"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-medium text-slate-200 group-hover:text-white">
                          {preset.label}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                            preset.tone === 'rose'
                              ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                              : preset.tone === 'amber'
                              ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                              : preset.tone === 'cyan'
                              ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                              : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                          }`}
                        >
                          {preset.badge}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 mt-1 leading-snug">{preset.description}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Workspace: Editor + Live Wire Output */}
            <div className="lg:col-span-8 space-y-5">
              <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
                <div className="px-4 py-2.5 border-b border-slate-800 flex items-center justify-between bg-slate-900">
                  <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                    <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                    <span>
                      Executing live through <strong className="text-slate-200">pgveil {proxyAddr}</strong> as{' '}
                      <strong className="text-emerald-300">{selectedProfile}</strong>
                    </span>
                  </div>
                  <button
                    onClick={runQuery}
                    disabled={running}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 text-slate-950 font-semibold text-xs transition shadow-lg shadow-emerald-500/20"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    {running ? 'Executing / Awaiting HITL...' : 'Run Through Wire Proxy'}
                  </button>
                </div>
                <textarea
                  value={sql}
                  onChange={(e) => setSql(e.target.value)}
                  onKeyDown={(e) => {
                    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                      e.preventDefault()
                      runQuery()
                    }
                  }}
                  rows={5}
                  spellCheck={false}
                  className="w-full bg-slate-950/90 text-emerald-200 font-mono text-sm p-4 focus:outline-none resize-y"
                  placeholder="Enter PostgreSQL query (Cmd/Ctrl + Enter to execute)..."
                />
              </div>

              {/* Inline Live HITL Banner when a query is paused on the wire! */}
              {pendingApprovals.length > 0 && (
                <div className="rounded-xl bg-amber-500/10 border border-amber-500/40 p-4 space-y-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2 text-amber-300 font-semibold text-sm">
                      <AlertTriangle className="w-4 h-4 animate-pulse" />
                      Live Query Paused on PostgreSQL Wire ({pendingApprovals.length} pending)
                    </div>
                    <span className="text-xs font-mono text-amber-200/80">{pendingApprovals[0].id}</span>
                  </div>
                  <pre className="text-xs font-mono bg-slate-950/80 border border-amber-500/20 rounded-lg p-3 text-amber-100 overflow-x-auto">
                    {pendingApprovals[0].sql}
                  </pre>
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <span className="text-xs text-amber-200/80">
                      Profile <strong>{pendingApprovals[0].role_profile}</strong> · Statement{' '}
                      <strong>{pendingApprovals[0].statement_type}</strong> · {pendingApprovals[0].reason}
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => resolveApproval(pendingApprovals[0].id, true)}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-semibold flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        Approve & Resume Wire
                      </button>
                      <button
                        onClick={() => resolveApproval(pendingApprovals[0].id, false)}
                        className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 text-xs font-semibold flex items-center gap-1.5"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                        Deny (SQLSTATE 42501)
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* Execution Result Card */}
              {pgResult && (
                <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      {pgResult.status === 'ok' ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-rose-400" />
                      )}
                      <span className="text-sm font-semibold">
                        {pgResult.status === 'ok'
                          ? `Wire Response (${pgResult.command_tag || `${pgResult.row_count ?? 0} rows`})`
                          : pgResult.status === 'blocked'
                          ? 'Blocked by pgveil Firewall'
                          : 'Connection Error'}
                      </span>
                      {pgResult.audit && (
                        <span
                          className={`text-[11px] font-mono px-2 py-0.5 rounded border ${decisionBadge(
                            pgResult.audit.decision
                          )}`}
                        >
                          {pgResult.audit.decision}
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                      {pgResult.audit && (
                        <span className="text-indigo-300">
                          proxy overhead: {pgResult.audit.proxy_overhead_us} µs
                        </span>
                      )}
                      {pgResult.duration_ms !== undefined && (
                        <span>total: {pgResult.duration_ms.toFixed(2)} ms</span>
                      )}
                    </div>
                  </div>

                  {/* Masked Entity Badges */}
                  {pgResult.audit && pgResult.audit.pii_fields_masked > 0 && (
                    <div className="px-4 py-2 bg-emerald-500/5 border-b border-slate-800 flex items-center gap-2 flex-wrap text-xs">
                      <EyeOff className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span className="text-emerald-300 font-medium">
                        {pgResult.audit.pii_fields_masked} PII cells masked on wire:
                      </span>
                      {Object.entries(pgResult.audit.pii_entities || {}).map(([k, v]) => (
                        <span
                          key={k}
                          className="px-1.5 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-200 font-mono text-[10.5px]"
                        >
                          {k}: {v}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* PostgreSQL Wire Notices (e.g. Row-Exfiltration Truncation) */}
                  {pgResult.notices && pgResult.notices.length > 0 && (
                    <div className="px-4 py-2.5 bg-amber-500/10 border-b border-amber-500/20 text-xs text-amber-200 space-y-1">
                      {pgResult.notices.map((n, i) => (
                        <div key={i} className="flex items-center gap-2 font-mono">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <span>{n}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Blocked Error Output */}
                  {pgResult.status !== 'ok' && (
                    <div className="p-4 space-y-2">
                      <div className="p-3.5 rounded-lg bg-rose-950/40 border border-rose-500/30 font-mono text-xs text-rose-200">
                        {pgResult.sqlstate && (
                          <span className="inline-block mr-2 px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 font-bold">
                            SQLSTATE {pgResult.sqlstate}
                          </span>
                        )}
                        {pgResult.error}
                      </div>
                      {pgResult.decision && (
                        <div className="flex items-center gap-3 text-xs text-slate-400 font-mono pt-1">
                          <span>AST statement: <strong className="text-slate-200">{pgResult.decision.statement_type}</strong></span>
                          <span>rule: <strong className="text-rose-300">{pgResult.decision.rule}</strong></span>
                          <span>risk: <strong className="text-rose-300">{pgResult.decision.risk_level}</strong></span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Data Table */}
                  {pgResult.status === 'ok' && pgResult.columns && pgResult.columns.length > 0 && (
                    <div className="overflow-x-auto max-h-[420px]">
                      <table className="w-full text-left border-collapse text-[11.5px] font-mono">
                        <thead className="bg-slate-950/90 sticky top-0 text-slate-400 border-b border-slate-800">
                          <tr>
                            {pgResult.columns.map((col) => (
                              <th key={col} className="px-2.5 py-2 font-semibold whitespace-nowrap">
                                {col}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {(pgResult.rows || []).map((row, rIdx) => (
                            <tr key={rIdx} className="hover:bg-slate-800/40">
                              {row.map((cell, cIdx) => {
                                const masked = isMaskedLook(cell)
                                return (
                                  <td
                                    key={cIdx}
                                    className={`px-2.5 py-1.5 whitespace-nowrap max-w-md truncate ${
                                      cell === null
                                        ? 'text-slate-600 italic'
                                        : masked
                                        ? 'text-emerald-300 bg-emerald-500/5'
                                        : 'text-slate-200'
                                    }`}
                                    title={cell ?? 'NULL'}
                                  >
                                    {cell === null ? 'NULL' : cell}
                                  </td>
                                )
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {pgResult.status === 'ok' && (!pgResult.columns || pgResult.columns.length === 0) && (
                    <div className="p-4 text-xs font-mono text-emerald-300">
                      Statement succeeded cleanly: {pgResult.command_tag}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 1.5: AUTOMATIC SCHEMA PII DISCOVERY */}
        {tab === 'discovery' && (
          <div className="space-y-5">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h2 className="text-lg font-semibold flex items-center gap-2">
                  <ScanSearch className="w-5 h-5 text-emerald-400" />
                  Automatic Schema PII &amp; Secrets Discovery
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Samples live PostgreSQL tables against 8 checksum-validated compliance packs (GDPR, KVKK, PCI-DSS, HIPAA, LGPD, PIPEDA, UK-GDPR, Secrets) and auto-generates pgveil policy rules.
                </p>
              </div>
              <button
                onClick={runDiscovery}
                disabled={discovering}
                className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 text-slate-950 font-semibold text-xs flex items-center gap-2 shadow-lg shadow-emerald-500/20"
              >
                <ScanSearch className="w-4 h-4" />
                {discovering ? 'Scanning Live Schema...' : 'Scan Live PostgreSQL Schema'}
              </button>
            </div>

            {discoveryErr && (
              <div className="rounded-xl bg-rose-950/40 border border-rose-500/40 p-4 text-xs font-mono text-rose-200">
                {discoveryErr}
              </div>
            )}

            {!discoveryReport && !discovering && (
              <div className="rounded-xl bg-slate-900/70 border border-slate-800 p-10 text-center space-y-3">
                <ScanSearch className="w-10 h-10 text-emerald-400/70 mx-auto" />
                <div className="text-sm text-slate-200 font-medium">Zero-Config Compliance Audit</div>
                <p className="text-xs text-slate-400 max-w-lg mx-auto">
                  Click <strong>Scan Live PostgreSQL Schema</strong> (or run <code>pgveil discover --dsn ...</code> in CLI) to automatically detect unmasked TCKNs, IBANs, credit cards, SSNs, emails, and leaked cloud secrets across every table.
                </p>
              </div>
            )}

            {discoveryReport && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
                <div className="lg:col-span-8 space-y-4">
                  <div className="grid grid-cols-3 gap-3">
                    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-3">
                      <div className="text-[11px] text-slate-400">Database / Tables</div>
                      <div className="text-sm font-mono font-bold text-white mt-0.5">
                        {discoveryReport.database} ({discoveryReport.tables_scanned} tables)
                      </div>
                    </div>
                    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-3">
                      <div className="text-[11px] text-slate-400">Columns Scanned</div>
                      <div className="text-sm font-mono font-bold text-cyan-300 mt-0.5">
                        {discoveryReport.columns_scanned}
                      </div>
                    </div>
                    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-3">
                      <div className="text-[11px] text-slate-400">Sensitive Columns Found</div>
                      <div className="text-sm font-mono font-bold text-amber-300 mt-0.5">
                        {discoveryReport.findings_count}
                      </div>
                    </div>
                  </div>

                  <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs font-mono">
                        <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="px-3 py-2.5">Table.Column</th>
                            <th className="px-3 py-2.5">Risk</th>
                            <th className="px-3 py-2.5">Compliance</th>
                            <th className="px-3 py-2.5">Strategy</th>
                            <th className="px-3 py-2.5">Masked Preview</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {discoveryReport.findings.map((f, idx) => (
                            <tr key={idx} className="hover:bg-slate-800/40">
                              <td className="px-3 py-2 text-slate-200 whitespace-nowrap">
                                <span className="text-slate-400">{f.table}.</span>
                                <strong className="text-white">{f.column}</strong>
                              </td>
                              <td className="px-3 py-2 whitespace-nowrap">
                                <span
                                  className={`px-1.5 py-0.5 rounded border text-[10px] ${
                                    f.risk_level === 'CRITICAL'
                                      ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                                      : f.risk_level === 'HIGH'
                                      ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                      : 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                                  }`}
                                >
                                  {f.risk_level}
                                </span>
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1">
                                  {f.compliance_packs.map((pk) => (
                                    <span
                                      key={pk}
                                      className="px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 text-[10px] uppercase"
                                    >
                                      {pk}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-3 py-2 text-indigo-300">{f.recommended_strategy}</td>
                              <td className="px-3 py-2 text-emerald-300 max-w-xs truncate" title={f.sample_masked}>
                                {f.sample_masked}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>

                <div className="lg:col-span-4 space-y-3">
                  <CodeBlock
                    title="Auto-Generated pgveil.yaml Policy Block"
                    code={discoveryReport.generated_yaml}
                    copied={copiedSnippet === 'discover_yaml'}
                    onCopy={() => copyText('discover_yaml', discoveryReport.generated_yaml)}
                  />
                  {discoveryReport.recommended_denied_tables && discoveryReport.recommended_denied_tables.length > 0 && (
                    <div className="rounded-lg bg-rose-500/10 border border-rose-500/30 p-3 text-xs font-mono text-rose-200">
                      Recommended denied_tables:{' '}
                      <strong>{discoveryReport.recommended_denied_tables.join(', ')}</strong>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* TAB 2: HITL APPROVALS QUEUE */}
        {tab === 'approvals' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold">Human-in-the-Loop (HITL) Approval Queue</h2>
                <p className="text-xs text-slate-400">
                  High-risk AI agent & developer write queries pause synchronously on the PostgreSQL wire until approved or denied.
                </p>
              </div>
              <button
                onClick={fetchInitialData}
                className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Refresh
              </button>
            </div>

            {approvals.length === 0 ? (
              <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-10 text-center text-slate-400 text-sm">
                No HITL approval requests yet. Run the <strong>Live HITL Hold (Scoped UPDATE)</strong> scenario in SQL Playground to watch a live query pause here!
              </div>
            ) : (
              <div className="space-y-3">
                {approvals.map((req) => (
                  <div
                    key={req.id}
                    className={`rounded-xl border p-4 space-y-3 ${
                      req.status === 'PENDING'
                        ? 'bg-amber-500/5 border-amber-500/40'
                        : 'bg-slate-900/70 border-slate-800'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                            req.status === 'PENDING'
                              ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                              : req.status === 'APPROVED'
                              ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                              : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                          }`}
                        >
                          {req.status}
                        </span>
                        <span className="font-mono text-xs text-slate-300">{req.id}</span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className="font-mono text-xs text-cyan-300">{req.role_profile}</span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className="font-mono text-xs text-slate-400">{req.statement_type}</span>
                      </div>
                      <span className="text-xs font-mono text-slate-500">{formatTime(req.created_at)}</span>
                    </div>

                    <pre className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg p-3 text-slate-200 overflow-x-auto">
                      {req.sql}
                    </pre>

                    <div className="flex items-center justify-between gap-3 flex-wrap text-xs text-slate-400">
                      <span>
                        {req.reason}
                        {req.reviewer && (
                          <span className="ml-2 text-slate-300">
                            — reviewed by <strong>{req.reviewer}</strong> ({req.reviewer_note})
                          </span>
                        )}
                      </span>
                      {req.status === 'PENDING' && (
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => resolveApproval(req.id, true)}
                            className="px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold flex items-center gap-1.5"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" /> Approve
                          </button>
                          <button
                            onClick={() => resolveApproval(req.id, false)}
                            className="px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 font-semibold flex items-center gap-1.5"
                          >
                            <XCircle className="w-3.5 h-3.5" /> Deny
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB 3: LIVE AUDIT STREAM */}
        {tab === 'audit' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h2 className="text-lg font-semibold">Live Wire Audit & Security Feed</h2>
                <p className="text-xs text-slate-400">
                  Real-time SSE stream of every PostgreSQL query inspected on the wire (mirrored asynchronously to Kafka when enabled).
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select
                  value={decisionFilter}
                  onChange={(e) => setDecisionFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200"
                >
                  <option value="">All Decisions</option>
                  <option value="MASKED">MASKED</option>
                  <option value="BLOCKED">BLOCKED</option>
                  <option value="TRUNCATED">TRUNCATED</option>
                  <option value="ALLOW">ALLOW</option>
                  <option value="HITL_APPROVED">HITL_APPROVED</option>
                  <option value="HITL_DENIED">HITL_DENIED</option>
                </select>
                <select
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200"
                >
                  <option value="">All Profiles</option>
                  {profiles.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                    <tr>
                      <th className="px-3.5 py-2.5">Time</th>
                      <th className="px-3.5 py-2.5">Decision</th>
                      <th className="px-3.5 py-2.5">Profile</th>
                      <th className="px-3.5 py-2.5">Stmt</th>
                      <th className="px-3.5 py-2.5">SQL Preview</th>
                      <th className="px-3.5 py-2.5 text-right">Rows</th>
                      <th className="px-3.5 py-2.5 text-right">Masked</th>
                      <th className="px-3.5 py-2.5 text-right">Proxy µs</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono">
                    {filteredEvents.length === 0 ? (
                      <tr>
                        <td colSpan={8} className="px-4 py-8 text-center text-slate-500 font-sans">
                          No audit events recorded yet. Run a query via Playground or connect with <code>psql</code> on port 6432.
                        </td>
                      </tr>
                    ) : (
                      filteredEvents.map((ev) => (
                        <tr key={ev.event_id} className="hover:bg-slate-800/40">
                          <td className="px-3.5 py-2 text-slate-400 whitespace-nowrap">{formatTime(ev.occurred_at)}</td>
                          <td className="px-3.5 py-2 whitespace-nowrap">
                            <span className={`px-2 py-0.5 rounded border text-[10px] ${decisionBadge(ev.decision)}`}>
                              {ev.decision}
                            </span>
                          </td>
                          <td className="px-3.5 py-2 text-cyan-300 whitespace-nowrap">{ev.role_profile}</td>
                          <td className="px-3.5 py-2 text-slate-300 whitespace-nowrap">{ev.statement_type}</td>
                          <td className="px-3.5 py-2 text-slate-200 max-w-md truncate" title={ev.raw_sql_preview}>
                            {ev.raw_sql_preview}
                          </td>
                          <td className="px-3.5 py-2 text-right text-slate-300">
                            {ev.rows_returned}
                            {ev.rows_truncated ? <span className="text-amber-400 ml-1">✂</span> : null}
                          </td>
                          <td className="px-3.5 py-2 text-right text-emerald-300">{ev.pii_fields_masked}</td>
                          <td className="px-3.5 py-2 text-right text-indigo-300">{ev.proxy_overhead_us} µs</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: POLICIES & HOT-RELOAD STUDIO */}
        {tab === 'policies' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-5 space-y-4">
              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 text-emerald-400" />
                  Built-in Compliance Packs
                </h3>
                <div className="space-y-2.5">
                  {Object.entries(compliancePacks).map(([pack, entities]) => (
                    <div key={pack} className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                      <div className="font-mono text-xs font-bold uppercase text-emerald-300">{pack}</div>
                      <div className="flex flex-wrap gap-1.5 mt-1.5">
                        {entities.map((ent) => (
                          <span
                            key={ent}
                            className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]"
                          >
                            {ent}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="lg:col-span-7 space-y-3">
              <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
                <div className="px-4 py-2.5 border-b border-slate-800 flex items-center justify-between bg-slate-900">
                  <div className="text-xs font-mono text-slate-300">
                    pgveil.yaml <span className="text-emerald-400 ml-1">v{policyVersion}</span>
                  </div>
                  <button
                    onClick={savePolicyYAML}
                    disabled={savingPolicy}
                    className="px-3.5 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-60 text-slate-950 font-semibold text-xs"
                  >
                    {savingPolicy ? 'Validating...' : 'Validate & Hot-Reload'}
                  </button>
                </div>
                {policyNotice && (
                  <div
                    className={`px-4 py-2 text-xs font-mono border-b ${
                      policyNotice.ok
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                        : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                    }`}
                  >
                    {policyNotice.msg}
                  </div>
                )}
                <textarea
                  value={policyYAML}
                  onChange={(e) => setPolicyYAML(e.target.value)}
                  rows={22}
                  spellCheck={false}
                  className="w-full bg-slate-950 text-slate-200 font-mono text-xs p-4 focus:outline-none leading-relaxed"
                />
              </div>
            </div>
          </div>
        )}

        {/* TAB 5: OBSERVABILITY & QUICK CONNECT */}
        {tab === 'observability' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 space-y-4">
              <h3 className="text-sm font-semibold flex items-center gap-2">
                <EyeOff className="w-4 h-4 text-emerald-400" />
                Masked PII Entities Breakdown
              </h3>
              {summary && Object.keys(summary.pii_by_entity || {}).length > 0 ? (
                <div className="space-y-2.5">
                  {Object.entries(summary.pii_by_entity)
                    .sort((a, b) => b[1] - a[1])
                    .map(([ent, count]) => {
                      const pct = Math.max(6, Math.round((count / Math.max(1, summary.total_pii_fields)) * 100))
                      return (
                        <div key={ent} className="space-y-1">
                          <div className="flex justify-between text-xs font-mono">
                            <span className="text-slate-300">{ent}</span>
                            <span className="text-emerald-300">{count}</span>
                          </div>
                          <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                            <div className="h-full bg-gradient-to-r from-emerald-500 to-cyan-400" style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                      )
                    })}
                </div>
              ) : (
                <p className="text-xs text-slate-500">Run queries in the Playground to populate live PII entity telemetry.</p>
              )}

              <div className="pt-3 border-t border-slate-800 flex items-center gap-2 flex-wrap text-xs font-mono">
                <a
                  href="/metrics"
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-cyan-300"
                >
                  Prometheus /metrics ↗
                </a>
                <a
                  href="/healthz"
                  target="_blank"
                  rel="noreferrer"
                  className="px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-700 text-emerald-300"
                >
                  /healthz ↗
                </a>
                <span className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-400">
                  Kafka Audit Pipeline: <strong className={summary?.kafka_enabled ? 'text-emerald-300' : 'text-slate-300'}>{summary?.kafka_enabled ? 'ENABLED' : 'LOCAL MODE'}</strong>
                </span>
              </div>
            </div>

            <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 space-y-4">
              <h3 className="text-sm font-semibold flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Zero-Code 1-Line Integration (psql · MCP · pgx · psycopg)
              </h3>
              <CodeBlock
                title="Connect with psql as AI Agent (Port 6432)"
                code={`psql "postgres://pgveil:pgveil_dev_password@localhost:6432/pgveil_demo?application_name=claude-mcp"`}
                copied={copiedSnippet === 'psql'}
                onCopy={() =>
                  copyText(
                    'psql',
                    'psql "postgres://pgveil:pgveil_dev_password@localhost:6432/pgveil_demo?application_name=claude-mcp"'
                  )
                }
              />
              <CodeBlock
                title="Native Zero-Dependency MCP Server (Claude Desktop / Cursor)"
                code={`{
  "mcpServers": {
    "pgveil-native": {
      "command": "pgveil",
      "args": ["mcp", "--config", "/path/to/pgveil.yaml", "--profile", "ai_agent"]
    }
  }
}`}
                copied={copiedSnippet === 'mcp_native'}
                onCopy={() =>
                  copyText(
                    'mcp_native',
                    'pgveil mcp --config configs/pgveil.yaml --profile ai_agent'
                  )
                }
              />
              <CodeBlock
                title="Or Wire Proxy Mode with Official Postgres MCP Server"
                code={`{
  "mcpServers": {
    "postgres-protected": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres",
        "postgres://pgveil:pgveil_dev_password@localhost:6432/pgveil_demo?application_name=claude-mcp"]
    }
  }
}`}
                copied={copiedSnippet === 'mcp'}
                onCopy={() =>
                  copyText(
                    'mcp',
                    'postgres://pgveil:pgveil_dev_password@localhost:6432/pgveil_demo?application_name=claude-mcp'
                  )
                }
              />
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

function KpiCard({
  label,
  value,
  icon,
  accent = 'text-white'
}: {
  label: string
  value: string | number
  icon: React.ReactNode
  accent?: string
}) {
  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800/90 px-3.5 py-2.5 flex items-center justify-between">
      <div>
        <div className="text-[11px] text-slate-400">{label}</div>
        <div className={`text-lg font-bold font-mono mt-0.5 ${accent}`}>{value}</div>
      </div>
      <div className="p-2 rounded-lg bg-slate-950/90 border border-slate-800">{icon}</div>
    </div>
  )
}

function CodeBlock({
  title,
  code,
  copied,
  onCopy
}: {
  title: string
  code: string
  copied: boolean
  onCopy: () => void
}) {
  return (
    <div className="rounded-lg bg-slate-950 border border-slate-800 overflow-hidden">
      <div className="px-3 py-1.5 border-b border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
        <span>{title}</span>
        <button onClick={onCopy} className="flex items-center gap-1 hover:text-white">
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="p-3 text-xs font-mono text-emerald-200 overflow-x-auto">{code}</pre>
    </div>
  )
}
