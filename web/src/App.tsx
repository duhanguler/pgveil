import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  Check,
  ChevronRight,
  Clock,
  Copy,
  Cpu,
  ExternalLink,
  Lock,
  Menu,
  Moon,
  Play,
  RefreshCw,
  ScanSearch,
  Search,
  Sliders,
  Sun,
  Terminal,
  X
} from 'lucide-react'
import { CodeEditor } from './components/CodeEditor'
import { CommandPalette } from './components/CommandPalette'
import { QUERY_PRESETS } from './data/presets'
import type {
  ApprovalRequest,
  AuditEvent,
  DiscoveryReport,
  FirewallDecision,
  PlaygroundResult,
  RoleProfile,
  Summary
} from './types'

type Tab = 'playground' | 'discovery' | 'approvals' | 'audit' | 'policies' | 'observability'

function statusTone(decision: string): { dot: string; color: string; bg: string; border: string } {
  switch (decision) {
    case 'MASKED':
    case 'APPROVED':
    case 'HITL_APPROVED':
      return { dot: 'var(--ok)', color: 'var(--ok)', bg: 'var(--ok-subtle)', border: 'var(--ok-border)' }
    case 'BLOCKED':
    case 'DENIED':
    case 'HITL_DENIED':
    case 'HITL_EXPIRED':
    case 'CRITICAL':
      return { dot: 'var(--danger)', color: 'var(--danger)', bg: 'var(--danger-subtle)', border: 'var(--danger-border)' }
    case 'TRUNCATED':
    case 'PENDING':
    case 'HIGH':
    case 'REQUIRE_HITL':
      return { dot: 'var(--warn)', color: 'var(--warn)', bg: 'var(--warn-subtle)', border: 'var(--warn-border)' }
    case 'WOULD_BLOCK':
    case 'WOULD_HITL':
    case 'ALLOW':
    default:
      return { dot: 'var(--info)', color: 'var(--ink-2)', bg: 'var(--bg-surface)', border: 'var(--border)' }
  }
}

function isMaskedCell(val: string | null): boolean {
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

function secondsLeft(expiresAt: string, nowMs: number): number {
  const diff = Math.ceil((new Date(expiresAt).getTime() - nowMs) / 1000)
  return Math.max(0, diff)
}

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('pgveil-theme')
    return saved === 'light' ? 'light' : 'dark'
  })
  const [tab, setTab] = useState<Tab>('playground')
  const [cmdOpen, setCmdOpen] = useState(false)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [nowMs, setNowMs] = useState(() => Date.now())

  // Live backend state
  const [summary, setSummary] = useState<Summary | null>(null)
  const [proxyAddr, setProxyAddr] = useState(':6432')
  const [version, setVersion] = useState('0.3.0')
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [profiles, setProfiles] = useState<RoleProfile[]>([])
  const [compliancePacks, setCompliancePacks] = useState<Record<string, string[]>>({})
  const [policyYAML, setPolicyYAML] = useState('')
  const [policyVersion, setPolicyVersion] = useState(1)
  const [sseConnected, setSseConnected] = useState(false)

  // SQL Workbench state
  const [selectedProfile, setSelectedProfile] = useState('ai_agent')
  const [sql, setSql] = useState(QUERY_PRESETS[0].sql)
  const [running, setRunning] = useState(false)
  const [pgResult, setPgResult] = useState<PlaygroundResult | null>(null)
  const [preflight, setPreflight] = useState<FirewallDecision | null>(null)

  // Discovery state
  const [discovering, setDiscovering] = useState(false)
  const [discoveryReport, setDiscoveryReport] = useState<DiscoveryReport | null>(null)
  const [discoveryErr, setDiscoveryErr] = useState<string | null>(null)
  const [riskFilter, setRiskFilter] = useState<string>('')

  // Audit ledger & inspector state
  const [decisionFilter, setDecisionFilter] = useState('')
  const [roleFilter, setRoleFilter] = useState('')
  const [auditSearch, setAuditSearch] = useState('')
  const [inspectedEvent, setInspectedEvent] = useState<AuditEvent | null>(null)

  // Policy & HITL state
  const [savingPolicy, setSavingPolicy] = useState(false)
  const [policyNotice, setPolicyNotice] = useState<{ ok: boolean; msg: string } | null>(null)
  const [hitlNote, setHitlNote] = useState('')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [connectTab, setConnectTab] = useState<'mcp' | 'psql' | 'wire_mcp' | 'python' | 'helm'>('mcp')

  const summaryTimerRef = useRef<number | null>(null)

  // Apply theme attribute to document root
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('pgveil-theme', theme)
  }, [theme])

  // Keyboard shortcuts: Cmd/Ctrl+K for Command Palette, 1-6 when not typing
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setCmdOpen((v) => !v)
        return
      }
      if (e.key === 'Escape') {
        setCmdOpen(false)
        setInspectedEvent(null)
        setMobileNavOpen(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  // Live 1s ticker only when pending HITL approvals exist
  const pendingApprovals = useMemo(() => approvals.filter((a) => a.status === 'PENDING'), [approvals])
  useEffect(() => {
    if (pendingApprovals.length === 0) return
    const t = window.setInterval(() => setNowMs(Date.now()), 1000)
    return () => window.clearInterval(t)
  }, [pendingApprovals.length])

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
        fetch('/api/v1/events?limit=150'),
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

  // Real-time SSE stream for audit & HITL events
  useEffect(() => {
    const es = new EventSource('/api/v1/events/stream')
    es.onopen = () => setSseConnected(true)
    es.onerror = () => setSseConnected(false)

    es.addEventListener('audit', (e: MessageEvent) => {
      try {
        const ev: AuditEvent = JSON.parse(e.data)
        setEvents((prev) => [ev, ...prev].slice(0, 250))
        if (summaryTimerRef.current) window.clearTimeout(summaryTimerRef.current)
        summaryTimerRef.current = window.setTimeout(() => fetchSummary(), 150)
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
        setNowMs(Date.now())
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

  // Live debounced AST pre-flight check as SQL or profile changes
  useEffect(() => {
    if (!sql.trim()) {
      setPreflight(null)
      return
    }
    const timer = window.setTimeout(async () => {
      try {
        const res = await fetch('/api/v1/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sql, profile: selectedProfile })
        })
        if (res.ok) {
          const d = await res.json()
          setPreflight(d.decision || null)
        }
      } catch {
        // ignore
      }
    }, 220)
    return () => window.clearTimeout(timer)
  }, [sql, selectedProfile])

  const executeSQL = useCallback(
    async (queryToRun?: string) => {
      const targetSQL = (queryToRun ?? sql).trim()
      if (!targetSQL || running) return
      setRunning(true)
      setPgResult(null)
      try {
        const res = await fetch('/api/v1/playground/query', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sql: targetSQL, profile: selectedProfile })
        })
        const data: PlaygroundResult = await res.json()
        setPgResult(data)
      } catch (err) {
        setPgResult({ status: 'connection_error', profile: selectedProfile, error: String(err) })
      } finally {
        setRunning(false)
        fetchSummary()
      }
    },
    [sql, running, selectedProfile, fetchSummary]
  )

  const runDiscovery = useCallback(async () => {
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
  }, [])

  const resolveApproval = async (id: string, approve: boolean, customNote?: string) => {
    try {
      await fetch(`/api/v1/approvals/${id}/${approve ? 'approve' : 'deny'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reviewer: 'operator',
          note: customNote || hitlNote || (approve ? 'Approved in Workbench' : 'Denied in Workbench')
        })
      })
      setHitlNote('')
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
        setPolicyNotice({ ok: false, msg: data.error || 'YAML validation failed' })
      } else {
        setPolicyVersion(data.version)
        setPolicyNotice({ ok: true, msg: `Hot-reloaded policy v${data.version} with zero dropped connections.` })
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
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 1500)
  }

  const activeProfileObj = profiles.find((p) => p.name === selectedProfile)
  const cleanPort = proxyAddr.replace('[::]', '')

  const filteredEvents = useMemo(() => {
    const q = auditSearch.trim().toLowerCase()
    return events.filter((e) => {
      if (decisionFilter && e.decision !== decisionFilter) return false
      if (roleFilter && e.role_profile !== roleFilter) return false
      if (q && !e.raw_sql_preview.toLowerCase().includes(q) && !e.policy_rule.toLowerCase().includes(q)) return false
      return true
    })
  }, [events, decisionFilter, roleFilter, auditSearch])

  const filteredFindings = useMemo(() => {
    if (!discoveryReport) return []
    if (!riskFilter) return discoveryReport.findings
    return discoveryReport.findings.filter((f) => f.risk_level === riskFilter)
  }, [discoveryReport, riskFilter])

  const navItems: { id: Tab; label: string; group: 'WORKBENCH' | 'GOVERNANCE'; icon: React.ReactNode; badge?: number }[] = [
    { id: 'playground', label: 'SQL Workbench', group: 'WORKBENCH', icon: <Terminal className="w-3.5 h-3.5" /> },
    { id: 'discovery', label: 'PII Discovery', group: 'WORKBENCH', icon: <ScanSearch className="w-3.5 h-3.5" /> },
    { id: 'approvals', label: 'HITL Queue', group: 'WORKBENCH', icon: <Clock className="w-3.5 h-3.5" />, badge: pendingApprovals.length },
    { id: 'audit', label: 'Audit Ledger', group: 'WORKBENCH', icon: <Activity className="w-3.5 h-3.5" /> },
    { id: 'policies', label: 'Policy Studio', group: 'GOVERNANCE', icon: <Sliders className="w-3.5 h-3.5" /> },
    { id: 'observability', label: 'Connect & Ops', group: 'GOVERNANCE', icon: <Cpu className="w-3.5 h-3.5" /> }
  ]

  const connectSnippets: Record<typeof connectTab, { title: string; subtitle: string; code: string }> = {
    mcp: {
      title: 'Native Zero-Node.js MCP Server (Claude Desktop / Cursor / Claude Code)',
      subtitle: 'Single Go binary over stdio — automatically hides denied_tables and enforces AST + PII masking.',
      code: `{
  "mcpServers": {
    "pgveil-postgres": {
      "command": "pgveil",
      "args": ["mcp", "--config", "/path/to/configs/pgveil.yaml", "--profile", "ai_agent"]
    }
  }
}`
    },
    psql: {
      title: 'Connect via psql on Port 6432',
      subtitle: 'Zero driver or schema changes — swap port 5432 → 6432 and pass application_name.',
      code: `psql "postgres://pgveil:pgveil_dev_password@127.0.0.1:6432/pgveil_demo?sslmode=disable&application_name=claude-mcp"`
    },
    wire_mcp: {
      title: 'Official Postgres MCP Server Through Wire Proxy',
      subtitle: 'Routes @modelcontextprotocol/server-postgres through pgveil with live HITL wire holds.',
      code: `{
  "mcpServers": {
    "postgres-wire": {
      "command": "npx",
      "args": [
        "-y", "@modelcontextprotocol/server-postgres",
        "postgres://pgveil:pgveil_dev_password@127.0.0.1:6432/pgveil_demo?sslmode=disable&application_name=claude-mcp"
      ]
    }
  }
}`
    },
    python: {
      title: 'Python AI SQL Agent (psycopg / LangChain / CrewAI)',
      subtitle: 'Works transparently with both Simple and Extended parameterized queries.',
      code: `import psycopg

DSN = "postgres://pgveil:pgveil_dev_password@127.0.0.1:6432/pgveil_demo?application_name=langchain-agent"
with psycopg.connect(DSN) as conn:
    rows = conn.execute("SELECT id, email, tckn, iban FROM customers LIMIT 5").fetchall()
    print(rows)  # All PII masked dynamically on the wire`
    },
    helm: {
      title: 'Production Kubernetes Helm Deployment',
      subtitle: 'Includes HPA, PodDisruptionBudget, NetworkPolicy, and Kafka Audit Worker.',
      code: `helm upgrade --install pgveil deploy/helm/pgveil \\
  --namespace database-security --create-namespace \\
  --set upstream.addr=postgres-primary.database.svc.cluster.local:5432 \\
  --set security.maskingSecret="$PGVEIL_MASKING_SECRET"`
    }
  }

  return (
    <div className="h-screen flex flex-col overflow-hidden" style={{ background: 'var(--bg-canvas)', color: 'var(--ink-1)' }}>
      {/* 44px Precision Top Command Bar */}
      <header
        className="h-11 shrink-0 border-b px-3 flex items-center justify-between gap-3"
        style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
      >
        {/* Brand + Live Target */}
        <div className="flex items-center gap-2.5 min-w-0">
          <button
            onClick={() => setMobileNavOpen((v) => !v)}
            className="lg:hidden p-1.5 rounded hover:opacity-80"
            style={{ color: 'var(--ink-2)' }}
            aria-label="Toggle navigation"
          >
            <Menu className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2">
            {/* Crisp monochrome geometric monogram */}
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="shrink-0">
              <path
                d="M12 2.5L20 6V12.5C20 17.2 16.6 20.6 12 22C7.4 20.6 4 17.2 4 12.5V6L12 2.5Z"
                stroke="currentColor"
                strokeWidth="1.9"
                strokeLinejoin="round"
              />
              <path d="M8.5 12.2L11 14.7L15.8 9.6" stroke="var(--ok)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <span className="font-semibold text-[13.5px] tracking-tight">pgveil</span>
            <span
              className="text-[10.5px] font-mono px-1.5 py-0.5 rounded border"
              style={{ borderColor: 'var(--border)', color: 'var(--ink-3)', background: 'var(--bg-surface)' }}
            >
              v{version}
            </span>
          </div>

          <span className="hidden sm:inline text-xs" style={{ color: 'var(--border-strong)' }}>
            /
          </span>
          <span className="hidden sm:inline text-xs font-mono truncate" style={{ color: 'var(--ink-2)' }}>
            wire <strong style={{ color: 'var(--ink-1)' }}>{cleanPort}</strong>
          </span>
        </div>

        {/* Center Command Palette Trigger */}
        <button
          onClick={() => setCmdOpen(true)}
          className="hidden md:flex items-center justify-between gap-4 w-full max-w-sm h-7 px-2.5 rounded-md border text-xs transition-colors"
          style={{ background: 'var(--bg-canvas)', borderColor: 'var(--border)', color: 'var(--ink-3)' }}
        >
          <span className="flex items-center gap-2 truncate">
            <Search className="w-3.5 h-3.5 shrink-0" />
            <span className="truncate">Jump to view, run scenario, switch role...</span>
          </span>
          <kbd
            className="text-[10px] font-mono px-1.5 py-0.2 rounded border shrink-0"
            style={{ borderColor: 'var(--border)', color: 'var(--ink-3)' }}
          >
            ⌘K
          </kbd>
        </button>

        {/* Right Inline Telemetry + Theme Switch */}
        <div className="flex items-center gap-3 text-[11.5px] font-mono tabular-nums shrink-0">
          <div className="hidden xl:flex items-center gap-3 pr-2 border-r" style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}>
            <span>
              <strong style={{ color: 'var(--ink-1)' }}>{(summary?.total_queries ?? 0).toLocaleString()}</strong> queries
            </span>
            <span>
              <strong style={{ color: 'var(--ok)' }}>{(summary?.total_pii_fields ?? 0).toLocaleString()}</strong> masked
            </span>
            <span>
              <strong style={{ color: (summary?.blocked_queries ?? 0) > 0 ? 'var(--danger)' : 'var(--ink-1)' }}>
                {(summary?.blocked_queries ?? 0).toLocaleString()}
              </strong>{' '}
              blocked
            </span>
            <span>
              <strong style={{ color: 'var(--ink-1)' }}>{Math.round(summary?.avg_proxy_overhead_us ?? 0)} µs</strong> avg
            </span>
          </div>

          <span className="flex items-center gap-1.5" style={{ color: 'var(--ink-2)' }} title="Real-time SSE event stream">
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{ background: sseConnected ? 'var(--ok)' : 'var(--ink-3)' }}
            />
            <span className="hidden sm:inline">{sseConnected ? 'Live' : 'Sync'}</span>
          </span>

          <button
            onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
            className="p-1.5 rounded-md border transition-colors"
            style={{ borderColor: 'var(--border)', color: 'var(--ink-2)', background: 'var(--bg-surface)' }}
            title={theme === 'dark' ? 'Switch to Light theme' : 'Switch to Dark theme'}
            aria-label="Toggle color theme"
          >
            {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          </button>

          <a
            href="/metrics"
            target="_blank"
            rel="noreferrer"
            className="hidden sm:flex items-center gap-1 px-2 py-1 rounded-md border text-[11px]"
            style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
            title="Prometheus /metrics"
          >
            /metrics
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </header>

      {/* Main Edge-to-Edge Workbench Body */}
      <div className="flex-1 flex min-h-0 relative">
        {/* Mobile Backdrop */}
        {mobileNavOpen && (
          <div
            className="fixed inset-0 z-30 bg-black/50 lg:hidden"
            onClick={() => setMobileNavOpen(false)}
          />
        )}

        {/* 216px Left Navigation & Session Context Rail */}
        <aside
          className={`${
            mobileNavOpen ? 'fixed top-11 bottom-0 left-0 z-40 flex' : 'hidden'
          } lg:static lg:flex w-[216px] shrink-0 border-r flex-col justify-between select-none`}
          style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
        >
          <div className="p-2.5 space-y-4 overflow-y-auto">
            {(['WORKBENCH', 'GOVERNANCE'] as const).map((group) => (
              <div key={group}>
                <div className="px-2 pb-1.5 text-[10px] font-semibold tracking-wider uppercase" style={{ color: 'var(--ink-3)' }}>
                  {group}
                </div>
                <div className="space-y-0.5">
                  {navItems
                    .filter((i) => i.group === group)
                    .map((item) => {
                      const active = tab === item.id
                      return (
                        <button
                          key={item.id}
                          onClick={() => {
                            setTab(item.id)
                            setMobileNavOpen(false)
                          }}
                          className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-[12.5px] font-medium transition-colors"
                          style={{
                            background: active ? 'var(--bg-active)' : 'transparent',
                            color: active ? 'var(--ink-1)' : 'var(--ink-2)'
                          }}
                        >
                          <span className="flex items-center gap-2">
                            <span style={{ color: active ? 'var(--ink-1)' : 'var(--ink-3)' }}>{item.icon}</span>
                            <span>{item.label}</span>
                          </span>
                          {item.badge ? (
                            <span
                              className="text-[10px] font-mono font-semibold px-1.5 py-0.2 rounded tabular-nums"
                              style={{ background: 'var(--warn-subtle)', color: 'var(--warn)', border: '1px solid var(--warn-border)' }}
                            >
                              {item.badge}
                            </span>
                          ) : null}
                        </button>
                      )
                    })}
                </div>
              </div>
            ))}
          </div>

          {/* Pinned Bottom Active Role Context */}
          <div className="border-t p-3 space-y-2" style={{ borderColor: 'var(--border)' }}>
            <div className="flex items-center justify-between text-[10px] font-semibold tracking-wider uppercase" style={{ color: 'var(--ink-3)' }}>
              <span>Session Role</span>
              <span className="font-mono">{activeProfileObj?.mode?.toUpperCase() || 'ENFORCE'}</span>
            </div>
            <div className="space-y-1">
              {(profiles.length
                ? profiles
                : [{ name: 'ai_agent' }, { name: 'analyst' }, { name: 'developer' }, { name: 'admin' }]
              ).map((p) => {
                const active = selectedProfile === p.name
                const maxRows = 'firewall' in p ? p.firewall.max_rows : 0
                return (
                  <button
                    key={p.name}
                    onClick={() => setSelectedProfile(p.name)}
                    className="w-full flex items-center justify-between px-2 py-1 rounded text-xs font-mono transition-colors"
                    style={{
                      background: active ? 'var(--bg-active)' : 'transparent',
                      color: active ? 'var(--ink-1)' : 'var(--ink-2)'
                    }}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        className="w-1.5 h-1.5 rounded-full"
                        style={{ background: active ? 'var(--ok)' : 'var(--border-strong)' }}
                      />
                      <span>{p.name}</span>
                    </span>
                    <span className="text-[10px]" style={{ color: 'var(--ink-3)' }}>
                      {maxRows > 0 ? `≤${maxRows}` : '∞'}
                    </span>
                  </button>
                )
              })}
            </div>
            {activeProfileObj && (
              <div
                className="pt-1.5 border-t text-[10.5px] font-mono flex items-center justify-between gap-2 whitespace-nowrap"
                style={{ borderColor: 'var(--border)', color: 'var(--ink-3)' }}
              >
                <span>{activeProfileObj.masking.enabled ? `${activeProfileObj.masking.compliance_packs?.length || 0} packs` : 'unmasked'}</span>
                <span style={{ color: 'var(--border-strong)' }}>·</span>
                <span>{activeProfileObj.firewall.block_pii_inference ? 'oracle guard' : 'standard'}</span>
              </div>
            )}
          </div>
        </aside>

        {/* Active View Surface */}
        <main className="flex-1 flex flex-col min-w-0 min-h-0 overflow-hidden">
          {/* ========================================================== */}
          {/* VIEW 1: SQL WORKBENCH (Full-Height Split Pane)             */}
          {/* ========================================================== */}
          {tab === 'playground' && (
            <div className="flex-1 flex flex-col min-h-0">
              {/* Workbench Action Toolbar */}
              <div
                className="shrink-0 border-b px-3.5 py-2 flex items-center justify-between gap-3 flex-wrap"
                style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
              >
                <div className="flex items-center gap-1.5 overflow-x-auto max-w-full py-0.5">
                  <span className="text-[11px] font-mono mr-1 shrink-0" style={{ color: 'var(--ink-3)' }}>
                    Scenarios:
                  </span>
                  {QUERY_PRESETS.slice(0, 7).map((preset) => {
                    const isCurrent = sql.trim() === preset.sql.trim()
                    const dotColor =
                      preset.category === 'firewall'
                        ? 'var(--danger)'
                        : preset.category === 'hitl'
                        ? 'var(--warn)'
                        : 'var(--ok)'
                    return (
                      <button
                        key={preset.id}
                        onClick={() => setSql(preset.sql)}
                        title={preset.hint}
                        className="flex items-center gap-1.5 px-2 py-1 rounded border text-[11.5px] whitespace-nowrap transition-colors"
                        style={{
                          background: isCurrent ? 'var(--bg-active)' : 'var(--bg-canvas)',
                          borderColor: isCurrent ? 'var(--border-strong)' : 'var(--border)',
                          color: isCurrent ? 'var(--ink-1)' : 'var(--ink-2)'
                        }}
                      >
                        <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: dotColor }} />
                        {preset.shortLabel}
                      </button>
                    )
                  })}
                  <select
                    aria-label="More scenarios"
                    value=""
                    onChange={(e) => {
                      const found = QUERY_PRESETS.find((p) => p.id === e.target.value)
                      if (found) setSql(found.sql)
                    }}
                    className="px-2 py-1 rounded border text-[11.5px] bg-transparent cursor-pointer"
                    style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
                  >
                    <option value="">More…</option>
                    {QUERY_PRESETS.slice(7).map((p) => (
                      <option key={p.id} value={p.id} style={{ background: 'var(--bg-panel)', color: 'var(--ink-1)' }}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => executeSQL()}
                    disabled={running}
                    className="h-7 px-3 rounded-md text-xs font-medium flex items-center gap-1.5 transition-opacity disabled:opacity-50"
                    style={{ background: 'var(--btn-bg)', color: 'var(--btn-fg)' }}
                  >
                    <Play className="w-3 h-3 fill-current" />
                    <span>{running ? 'Executing…' : 'Run Query'}</span>
                    <kbd className="text-[10px] font-mono opacity-60 ml-1">⌘↵</kbd>
                  </button>
                </div>
              </div>

              {/* Top Split: Syntax-Highlighted SQL Editor */}
              <div className="shrink-0">
                <CodeEditor
                  value={sql}
                  onChange={setSql}
                  language="sql"
                  minRows={5}
                  maxHeightClass="max-h-[210px]"
                  onRunShortcut={() => executeSQL()}
                  placeholder="Write any PostgreSQL query (Cmd/Ctrl + Enter to run live through wire proxy :6432)..."
                />
              </div>

              {/* AST Pre-Flight & Telemetry Status Strip */}
              <div
                className="shrink-0 border-y px-3.5 h-8 flex items-center justify-between gap-4 text-[11px] font-mono tabular-nums overflow-x-auto"
                style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', color: 'var(--ink-2)' }}
              >
                <div className="flex items-center gap-3 whitespace-nowrap">
                  <span>
                    profile: <strong style={{ color: 'var(--ink-1)' }}>{selectedProfile}</strong>
                  </span>
                  {preflight && (
                    <>
                      <span style={{ color: 'var(--border-strong)' }}>·</span>
                      <span className="flex items-center gap-1.5">
                        <span
                          className="w-1.5 h-1.5 rounded-full"
                          style={{
                            background:
                              preflight.action === 'BLOCK'
                                ? 'var(--danger)'
                                : preflight.action === 'REQUIRE_HITL'
                                ? 'var(--warn)'
                                : 'var(--ok)'
                          }}
                        />
                        <span>
                          AST pre-flight: <strong style={{ color: 'var(--ink-1)' }}>{preflight.statement_type}</strong>{' '}
                          ({preflight.action === 'ALLOW' ? 'allowed' : preflight.rule})
                        </span>
                      </span>
                      {preflight.tables && preflight.tables.length > 0 && (
                        <>
                          <span style={{ color: 'var(--border-strong)' }}>·</span>
                          <span>tables: {preflight.tables.join(', ')}</span>
                        </>
                      )}
                    </>
                  )}
                </div>

                <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
                  {pgResult?.audit && (
                    <>
                      <span>
                        proxy: <strong style={{ color: 'var(--ink-1)' }}>{pgResult.audit.proxy_overhead_us} µs</strong>
                      </span>
                      {pgResult.audit.pii_fields_masked > 0 && (
                        <span style={{ color: 'var(--ok)' }}>
                          {pgResult.audit.pii_fields_masked} PII cells masked
                        </span>
                      )}
                    </>
                  )}
                  {pgResult?.duration_ms !== undefined && (
                    <span>total: {pgResult.duration_ms.toFixed(2)} ms</span>
                  )}
                </div>
              </div>

              {/* Live Synchronous HITL Wire Hold Bar */}
              {pendingApprovals.length > 0 && (
                <div
                  className="shrink-0 border-b px-4 py-2.5 flex items-center justify-between gap-4 flex-wrap"
                  style={{ background: 'var(--warn-subtle)', borderColor: 'var(--warn-border)' }}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span className="w-2 h-2 rounded-full animate-pulse shrink-0" style={{ background: 'var(--warn)' }} />
                    <div className="text-xs min-w-0">
                      <span className="font-semibold" style={{ color: 'var(--warn)' }}>
                        Wire connection paused ({pendingApprovals[0].id})
                      </span>
                      <span className="mx-2 font-mono text-[11px]" style={{ color: 'var(--ink-2)' }}>
                        {secondsLeft(pendingApprovals[0].expires_at, nowMs)}s left
                      </span>
                      <code className="text-[11px] truncate block sm:inline" style={{ color: 'var(--ink-1)' }}>
                        {pendingApprovals[0].sql}
                      </code>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => resolveApproval(pendingApprovals[0].id, true)}
                      className="h-7 px-3 rounded text-xs font-medium"
                      style={{ background: 'var(--btn-bg)', color: 'var(--btn-fg)' }}
                    >
                      Approve &amp; Resume
                    </button>
                    <button
                      onClick={() => resolveApproval(pendingApprovals[0].id, false)}
                      className="h-7 px-3 rounded border text-xs font-medium"
                      style={{ borderColor: 'var(--danger-border)', color: 'var(--danger)', background: 'var(--danger-subtle)' }}
                    >
                      Deny
                    </button>
                  </div>
                </div>
              )}

              {/* Bottom Split: Dense Wire Response Grid or Diagnostic */}
              <div className="flex-1 flex flex-col min-h-0 overflow-hidden" style={{ background: 'var(--bg-canvas)' }}>
                {!pgResult && !running && (
                  <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
                    <div className="text-xs font-mono" style={{ color: 'var(--ink-3)' }}>
                      Press <kbd className="px-1.5 py-0.5 rounded border mx-1" style={{ borderColor: 'var(--border)' }}>⌘↵</kbd> or click{' '}
                      <strong style={{ color: 'var(--ink-2)' }}>Run Query</strong> to execute live over PostgreSQL wire port{' '}
                      <code style={{ color: 'var(--ink-2)' }}>{cleanPort}</code>.
                    </div>
                  </div>
                )}

                {running && !pgResult && (
                  <div className="flex-1 flex items-center justify-center text-xs font-mono" style={{ color: 'var(--ink-3)' }}>
                    Executing on wire {cleanPort} as {selectedProfile}…
                  </div>
                )}

                {pgResult && pgResult.status !== 'ok' && (
                  <div className="p-5 max-w-3xl space-y-4 overflow-y-auto">
                    <div
                      className="rounded-md border-l-2 border p-4 space-y-2.5"
                      style={{
                        borderColor: 'var(--border)',
                        borderLeftColor: 'var(--danger)',
                        background: 'var(--bg-panel)'
                      }}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 text-xs font-semibold" style={{ color: 'var(--danger)' }}>
                          <span className="w-2 h-2 rounded-full" style={{ background: 'var(--danger)' }} />
                          PostgreSQL Wire Firewall Rejection
                        </div>
                        {pgResult.sqlstate && (
                          <span
                            className="text-[11px] font-mono px-1.5 py-0.5 rounded border"
                            style={{ borderColor: 'var(--danger-border)', color: 'var(--danger)', background: 'var(--danger-subtle)' }}
                          >
                            SQLSTATE {pgResult.sqlstate}
                          </span>
                        )}
                      </div>
                      <pre className="text-xs font-mono whitespace-pre-wrap leading-relaxed" style={{ color: 'var(--ink-1)' }}>
                        {pgResult.error}
                      </pre>
                      {pgResult.decision && (
                        <div
                          className="pt-2.5 border-t flex flex-wrap items-start gap-x-7 gap-y-2.5 text-[11px] font-mono"
                          style={{ borderColor: 'var(--border)' }}
                        >
                          <div>
                            <div style={{ color: 'var(--ink-3)' }}>AST Statement</div>
                            <div className="mt-0.5" style={{ color: 'var(--ink-1)' }}>{pgResult.decision.statement_type}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--ink-3)' }}>Rule</div>
                            <div className="mt-0.5" style={{ color: 'var(--danger)' }}>{pgResult.decision.rule}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--ink-3)' }}>Risk</div>
                            <div className="mt-0.5" style={{ color: 'var(--ink-1)' }}>{pgResult.decision.risk_level}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--ink-3)' }}>Fingerprint</div>
                            <div className="mt-0.5" style={{ color: 'var(--ink-2)' }}>{pgResult.decision.fingerprint}</div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {pgResult && pgResult.status === 'ok' && (
                  <div className="flex-1 flex flex-col min-h-0">
                    {/* Sub-header: Wire Notices & Masked Entity Breakdown */}
                    {(pgResult.notices?.length || (pgResult.audit && pgResult.audit.pii_fields_masked > 0)) ? (
                      <div
                        className="shrink-0 border-b px-3.5 py-1.5 flex items-center justify-between gap-3 flex-wrap text-[11px] font-mono"
                        style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
                      >
                        <div className="flex items-center gap-2 flex-wrap">
                          {pgResult.audit && pgResult.audit.pii_fields_masked > 0 && (
                            <>
                              <span className="flex items-center gap-1.5" style={{ color: 'var(--ok)' }}>
                                <Lock className="w-3 h-3" />
                                Masked on wire:
                              </span>
                              {Object.entries(pgResult.audit.pii_entities || {}).map(([k, v]) => (
                                <span
                                  key={k}
                                  className="px-1.5 py-0.2 rounded border"
                                  style={{ borderColor: 'var(--border)', background: 'var(--bg-surface)', color: 'var(--ink-2)' }}
                                >
                                  {k}={v}
                                </span>
                              ))}
                            </>
                          )}
                        </div>
                        {pgResult.notices && pgResult.notices.length > 0 && (
                          <div style={{ color: 'var(--warn)' }}>{pgResult.notices[0]}</div>
                        )}
                      </div>
                    ) : null}

                    {/* Dense TablePlus-style Result Grid */}
                    {pgResult.columns && pgResult.columns.length > 0 ? (
                      <div className="flex-1 overflow-auto">
                        <table className="w-full text-left border-collapse font-mono text-[12px] tabular-nums">
                          <thead
                            className="sticky top-0 z-10 border-b"
                            style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', color: 'var(--ink-3)' }}
                          >
                            <tr>
                              <th className="w-9 px-2 py-1.5 text-right font-normal border-r select-none" style={{ borderColor: 'var(--border)' }}>
                                #
                              </th>
                              {pgResult.columns.map((col) => (
                                <th
                                  key={col}
                                  className="px-2.5 py-1.5 font-medium whitespace-nowrap border-r last:border-r-0"
                                  style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
                                >
                                  {col}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {(pgResult.rows || []).map((row, rIdx) => (
                              <tr
                                key={rIdx}
                                className="border-b transition-colors hover:bg-[var(--bg-hover)]"
                                style={{ borderColor: 'var(--border)' }}
                              >
                                <td
                                  className="px-2 py-1.5 text-right border-r select-none text-[11px]"
                                  style={{ borderColor: 'var(--border)', color: 'var(--ink-3)', background: 'var(--bg-panel)' }}
                                >
                                  {rIdx + 1}
                                </td>
                                {row.map((cell, cIdx) => {
                                  const masked = isMaskedCell(cell)
                                  return (
                                    <td
                                      key={cIdx}
                                      className="px-2.5 py-1.5 whitespace-nowrap max-w-[380px] truncate border-r last:border-r-0"
                                      style={{
                                        borderColor: 'var(--border)',
                                        color: cell === null ? 'var(--ink-3)' : masked ? 'var(--ok)' : 'var(--ink-1)',
                                        background: masked ? 'var(--ok-subtle)' : 'transparent'
                                      }}
                                      title={cell ?? 'NULL'}
                                    >
                                      {cell === null ? <span className="italic">NULL</span> : cell}
                                    </td>
                                  )
                                })}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <div className="p-5 font-mono text-xs" style={{ color: 'var(--ok)' }}>
                        ✓ {pgResult.command_tag || 'Command executed successfully'}
                      </div>
                    )}

                    {/* Bottom Result Status Bar */}
                    <div
                      className="shrink-0 h-7 border-t px-3.5 flex items-center justify-between text-[11px] font-mono tabular-nums"
                      style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)', color: 'var(--ink-3)' }}
                    >
                      <span>{pgResult.command_tag || `${pgResult.row_count ?? 0} rows`}</span>
                      <span>
                        {pgResult.audit?.decision || 'OK'} · {pgResult.duration_ms?.toFixed(2)} ms
                      </span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ========================================================== */}
          {/* VIEW 2: AUTOMATIC SCHEMA PII DISCOVERY                     */}
          {/* ========================================================== */}
          {tab === 'discovery' && (
            <div className="flex-1 flex flex-col min-h-0">
              <div
                className="shrink-0 border-b px-4 py-2.5 flex items-center justify-between gap-3 flex-wrap"
                style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
              >
                <div className="flex items-center gap-4 flex-wrap">
                  <div>
                    <h1 className="text-sm font-semibold">Schema PII &amp; Secrets Discovery</h1>
                    <p className="text-[11.5px]" style={{ color: 'var(--ink-3)' }}>
                      Samples live tables across 8 checksum-validated compliance packs and synthesizes pgveil.yaml rules.
                    </p>
                  </div>
                  {discoveryReport && (
                    <div className="flex items-center gap-3 text-xs font-mono tabular-nums pl-4 border-l" style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}>
                      <span><strong style={{ color: 'var(--ink-1)' }}>{discoveryReport.tables_scanned}</strong> tables</span>
                      <span><strong style={{ color: 'var(--ink-1)' }}>{discoveryReport.columns_scanned}</strong> cols</span>
                      <span><strong style={{ color: 'var(--warn)' }}>{discoveryReport.findings_count}</strong> findings</span>
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  {discoveryReport && (
                    <div className="flex items-center rounded-md border overflow-hidden text-[11px]" style={{ borderColor: 'var(--border)' }}>
                      {['', 'CRITICAL', 'HIGH', 'MEDIUM'].map((rk) => (
                        <button
                          key={rk || 'all'}
                          onClick={() => setRiskFilter(rk)}
                          className="px-2.5 py-1 font-mono transition-colors"
                          style={{
                            background: riskFilter === rk ? 'var(--bg-active)' : 'transparent',
                            color: riskFilter === rk ? 'var(--ink-1)' : 'var(--ink-3)'
                          }}
                        >
                          {rk || 'All'}
                        </button>
                      ))}
                    </div>
                  )}
                  <button
                    onClick={runDiscovery}
                    disabled={discovering}
                    className="h-7 px-3 rounded-md text-xs font-medium flex items-center gap-1.5 disabled:opacity-50"
                    style={{ background: 'var(--btn-bg)', color: 'var(--btn-fg)' }}
                  >
                    <ScanSearch className="w-3.5 h-3.5" />
                    {discovering ? 'Scanning…' : 'Scan Live Schema'}
                  </button>
                </div>
              </div>

              {discoveryErr && (
                <div className="m-4 p-3 rounded border text-xs font-mono" style={{ borderColor: 'var(--danger-border)', background: 'var(--danger-subtle)', color: 'var(--danger)' }}>
                  {discoveryErr}
                </div>
              )}

              {!discoveryReport && !discovering && (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center gap-3">
                  <ScanSearch className="w-7 h-7" style={{ color: 'var(--ink-3)' }} />
                  <div className="text-sm font-medium">Zero-Config Database PII Audit</div>
                  <p className="text-xs max-w-md" style={{ color: 'var(--ink-3)' }}>
                    Run <strong style={{ color: 'var(--ink-2)' }}>Scan Live Schema</strong> or execute{' '}
                    <code className="px-1.5 py-0.5 rounded border" style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}>
                      pgveil discover --format yaml
                    </code>{' '}
                    to locate unmasked TCKN, IBAN, credit cards, SSN, CPF, SIN, NINO, and leaked cloud secrets.
                  </p>
                </div>
              )}

              {discoveryReport && (
                <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 min-h-0">
                  {/* Left 8 cols: Dense Findings Matrix */}
                  <div className="lg:col-span-8 border-r overflow-auto min-h-0" style={{ borderColor: 'var(--border)' }}>
                    <table className="w-full text-left border-collapse font-mono text-[12px] tabular-nums">
                      <thead
                        className="sticky top-0 z-10 border-b"
                        style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', color: 'var(--ink-3)' }}
                      >
                        <tr>
                          <th className="px-3 py-2 font-medium">Table.Column</th>
                          <th className="px-3 py-2 font-medium">Severity</th>
                          <th className="px-3 py-2 font-medium">Compliance</th>
                          <th className="px-3 py-2 font-medium">Strategy</th>
                          <th className="px-3 py-2 font-medium">Masked Preview</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredFindings.map((f, i) => {
                          const tone = statusTone(f.risk_level)
                          return (
                            <tr
                              key={i}
                              className="border-b transition-colors hover:bg-[var(--bg-hover)]"
                              style={{ borderColor: 'var(--border)' }}
                            >
                              <td className="px-3 py-2 whitespace-nowrap">
                                <span style={{ color: 'var(--ink-3)' }}>{f.table}.</span>
                                <strong style={{ color: 'var(--ink-1)' }}>{f.column}</strong>
                              </td>
                              <td className="px-3 py-2 whitespace-nowrap">
                                <span className="inline-flex items-center gap-1.5 text-[11px]" style={{ color: tone.color }}>
                                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: tone.dot }} />
                                  {f.risk_level}
                                </span>
                              </td>
                              <td className="px-3 py-2">
                                <div className="flex flex-wrap gap-1">
                                  {f.compliance_packs.map((pk) => (
                                    <span
                                      key={pk}
                                      className="px-1.5 py-0.2 rounded border text-[10px] uppercase"
                                      style={{ borderColor: 'var(--border)', background: 'var(--bg-surface)', color: 'var(--ink-2)' }}
                                    >
                                      {pk}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-3 py-2" style={{ color: 'var(--ink-2)' }}>
                                {f.recommended_strategy}
                              </td>
                              <td className="px-3 py-2 max-w-[260px] truncate" style={{ color: 'var(--ok)' }} title={f.sample_masked}>
                                {f.sample_masked}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>

                  {/* Right 4 cols: Highlighted Auto-Generated YAML */}
                  <div className="lg:col-span-4 flex flex-col min-h-0" style={{ background: 'var(--bg-panel)' }}>
                    <div
                      className="shrink-0 h-9 border-b px-3 flex items-center justify-between text-[11.5px] font-mono"
                      style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
                    >
                      <span>Generated pgveil.yaml snippet</span>
                      <button
                        onClick={() => copyText('disc-yaml', discoveryReport.generated_yaml)}
                        className="flex items-center gap-1 px-2 py-0.5 rounded border text-[11px]"
                        style={{ borderColor: 'var(--border)', color: 'var(--ink-1)' }}
                      >
                        {copiedKey === 'disc-yaml' ? <Check className="w-3 h-3" style={{ color: 'var(--ok)' }} /> : <Copy className="w-3 h-3" />}
                        {copiedKey === 'disc-yaml' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div className="flex-1 min-h-0 overflow-hidden">
                      <CodeEditor
                        value={discoveryReport.generated_yaml}
                        language="yaml"
                        readOnly
                        minRows={18}
                        maxHeightClass="h-full"
                      />
                    </div>
                    {discoveryReport.recommended_denied_tables && discoveryReport.recommended_denied_tables.length > 0 && (
                      <div
                        className="shrink-0 border-t px-3 py-2 text-[11px] font-mono flex items-center justify-between"
                        style={{ borderColor: 'var(--border)', background: 'var(--danger-subtle)', color: 'var(--danger)' }}
                      >
                        <span>Recommend denying: {discoveryReport.recommended_denied_tables.join(', ')}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ========================================================== */}
          {/* VIEW 3: HITL APPROVAL QUEUE                                */}
          {/* ========================================================== */}
          {tab === 'approvals' && (
            <div className="flex-1 flex flex-col min-h-0">
              <div
                className="shrink-0 border-b px-4 py-2.5 flex items-center justify-between"
                style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
              >
                <div>
                  <h1 className="text-sm font-semibold">Human-in-the-Loop Approval Queue</h1>
                  <p className="text-[11.5px]" style={{ color: 'var(--ink-3)' }}>
                    Scoped AI-agent &amp; developer write queries pause synchronously on the wire until reviewed.
                  </p>
                </div>
                <button
                  onClick={fetchInitialData}
                  className="h-7 px-2.5 rounded border text-xs flex items-center gap-1.5"
                  style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
                >
                  <RefreshCw className="w-3.5 h-3.5" /> Refresh
                </button>
              </div>

              <div className="flex-1 overflow-y-auto divide-y" style={{ borderColor: 'var(--border)' }}>
                {approvals.length === 0 ? (
                  <div className="p-12 text-center text-xs" style={{ color: 'var(--ink-3)' }}>
                    No HITL approval requests yet. Trigger <strong>HITL UPDATE</strong> in SQL Workbench to pause a live wire query here.
                  </div>
                ) : (
                  approvals.map((req) => {
                    const tone = statusTone(req.status)
                    const isPending = req.status === 'PENDING'
                    return (
                      <div
                        key={req.id}
                        className="p-4 space-y-3"
                        style={{ background: isPending ? 'var(--warn-subtle)' : 'transparent' }}
                      >
                        <div className="flex items-center justify-between gap-2 flex-wrap text-xs font-mono">
                          <div className="flex items-center gap-2.5">
                            <span className="inline-flex items-center gap-1.5 font-medium" style={{ color: tone.color }}>
                              <span className="w-1.5 h-1.5 rounded-full" style={{ background: tone.dot }} />
                              {req.status}
                            </span>
                            <span style={{ color: 'var(--ink-1)' }}>{req.id}</span>
                            <span style={{ color: 'var(--ink-3)' }}>·</span>
                            <span style={{ color: 'var(--ink-2)' }}>{req.role_profile}</span>
                            <span style={{ color: 'var(--ink-3)' }}>·</span>
                            <span style={{ color: 'var(--ink-2)' }}>{req.statement_type}</span>
                          </div>
                          <div className="tabular-nums" style={{ color: isPending ? 'var(--warn)' : 'var(--ink-3)' }}>
                            {isPending ? `${secondsLeft(req.expires_at, nowMs)}s remaining` : formatTime(req.created_at)}
                          </div>
                        </div>

                        <div className="rounded border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                          <CodeEditor value={req.sql} language="sql" readOnly minRows={2} maxHeightClass="max-h-36" />
                        </div>

                        <div className="flex items-center justify-between gap-3 flex-wrap">
                          <span className="text-xs" style={{ color: 'var(--ink-2)' }}>
                            {req.reason}
                            {req.reviewer ? ` — ${req.reviewer} (${req.reviewer_note})` : ''}
                          </span>
                          {isPending && (
                            <div className="flex items-center gap-2">
                              <input
                                value={hitlNote}
                                onChange={(e) => setHitlNote(e.target.value)}
                                placeholder="Optional reviewer note…"
                                className="h-7 px-2.5 rounded border text-xs bg-transparent focus:outline-none"
                                style={{ borderColor: 'var(--border)', color: 'var(--ink-1)' }}
                              />
                              <button
                                onClick={() => resolveApproval(req.id, true)}
                                className="h-7 px-3 rounded text-xs font-medium"
                                style={{ background: 'var(--btn-bg)', color: 'var(--btn-fg)' }}
                              >
                                Approve
                              </button>
                              <button
                                onClick={() => resolveApproval(req.id, false)}
                                className="h-7 px-3 rounded border text-xs font-medium"
                                style={{ borderColor: 'var(--danger-border)', color: 'var(--danger)' }}
                              >
                                Deny
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          )}

          {/* ========================================================== */}
          {/* VIEW 4: AUDIT LEDGER + SLIDE-OVER INSPECTOR DRAWER         */}
          {/* ========================================================== */}
          {tab === 'audit' && (
            <div className="relative flex-1 flex min-h-0">
              <div className="flex-1 flex flex-col min-w-0 min-h-0">
                <div
                  className="shrink-0 border-b px-4 py-2 flex items-center justify-between gap-3 flex-wrap"
                  style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
                >
                  <div className="flex items-center gap-2 flex-1 min-w-[200px] max-w-md">
                    <Search className="w-3.5 h-3.5 shrink-0" style={{ color: 'var(--ink-3)' }} />
                    <input
                      value={auditSearch}
                      onChange={(e) => setAuditSearch(e.target.value)}
                      placeholder="Filter SQL or firewall rule…"
                      className="w-full bg-transparent text-xs font-mono focus:outline-none"
                      style={{ color: 'var(--ink-1)' }}
                    />
                  </div>
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <select
                      value={decisionFilter}
                      onChange={(e) => setDecisionFilter(e.target.value)}
                      className="h-7 px-2 rounded border bg-transparent"
                      style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
                    >
                      <option value="">All Decisions</option>
                      {['MASKED', 'BLOCKED', 'TRUNCATED', 'ALLOW', 'HITL_APPROVED', 'HITL_DENIED', 'WOULD_BLOCK'].map((d) => (
                        <option key={d} value={d} style={{ background: 'var(--bg-panel)', color: 'var(--ink-1)' }}>
                          {d}
                        </option>
                      ))}
                    </select>
                    <select
                      value={roleFilter}
                      onChange={(e) => setRoleFilter(e.target.value)}
                      className="h-7 px-2 rounded border bg-transparent"
                      style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
                    >
                      <option value="">All Roles</option>
                      {profiles.map((p) => (
                        <option key={p.name} value={p.name} style={{ background: 'var(--bg-panel)', color: 'var(--ink-1)' }}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="flex-1 overflow-auto">
                  <table className="w-full text-left border-collapse font-mono text-[11.5px] tabular-nums">
                    <thead
                      className="sticky top-0 z-10 border-b"
                      style={{ background: 'var(--bg-surface)', borderColor: 'var(--border)', color: 'var(--ink-3)' }}
                    >
                      <tr>
                        <th className="px-3 py-2 font-medium">Time</th>
                        <th className="px-3 py-2 font-medium">Decision</th>
                        <th className="px-3 py-2 font-medium">Role</th>
                        <th className="px-3 py-2 font-medium">Stmt</th>
                        <th className="px-3 py-2 font-medium">Query</th>
                        <th className="px-3 py-2 font-medium text-right">Rows</th>
                        <th className="px-3 py-2 font-medium text-right">Masked</th>
                        <th className="px-3 py-2 font-medium text-right">Proxy µs</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredEvents.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="px-4 py-10 text-center font-sans text-xs" style={{ color: 'var(--ink-3)' }}>
                            No audit events matching filters.
                          </td>
                        </tr>
                      ) : (
                        filteredEvents.map((ev) => {
                          const tone = statusTone(ev.decision)
                          const isSelected = inspectedEvent?.event_id === ev.event_id
                          return (
                            <tr
                              key={ev.event_id}
                              onClick={() => setInspectedEvent(ev)}
                              className="border-b cursor-pointer transition-colors hover:bg-[var(--bg-hover)]"
                              style={{
                                borderColor: 'var(--border)',
                                background: isSelected ? 'var(--bg-active)' : 'transparent'
                              }}
                            >
                              <td className="px-3 py-1.5 whitespace-nowrap" style={{ color: 'var(--ink-3)' }}>
                                {formatTime(ev.occurred_at)}
                              </td>
                              <td className="px-3 py-1.5 whitespace-nowrap">
                                <span className="inline-flex items-center gap-1.5" style={{ color: tone.color }}>
                                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: tone.dot }} />
                                  {ev.decision}
                                </span>
                              </td>
                              <td className="px-3 py-1.5 whitespace-nowrap" style={{ color: 'var(--ink-2)' }}>
                                {ev.role_profile}
                              </td>
                              <td className="px-3 py-1.5 whitespace-nowrap" style={{ color: 'var(--ink-2)' }}>
                                {ev.statement_type}
                              </td>
                              <td className="px-3 py-1.5 max-w-md truncate" style={{ color: 'var(--ink-1)' }}>
                                {ev.raw_sql_preview}
                              </td>
                              <td className="px-3 py-1.5 text-right" style={{ color: 'var(--ink-2)' }}>
                                {ev.rows_returned}
                                {ev.rows_truncated ? ' ✂' : ''}
                              </td>
                              <td className="px-3 py-1.5 text-right" style={{ color: ev.pii_fields_masked > 0 ? 'var(--ok)' : 'var(--ink-3)' }}>
                                {ev.pii_fields_masked}
                              </td>
                              <td className="px-3 py-1.5 text-right" style={{ color: 'var(--ink-2)' }}>
                                {ev.proxy_overhead_us}
                              </td>
                            </tr>
                          )
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Right-Side Event Inspector Slide-Over Drawer */}
              {inspectedEvent && (
                <aside
                  className="absolute inset-y-0 right-0 z-20 w-full max-w-[420px] border-l flex flex-col overflow-y-auto shadow-2xl"
                  style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
                >
                  <div className="h-10 px-3.5 border-b flex items-center justify-between text-xs font-mono shrink-0" style={{ borderColor: 'var(--border)' }}>
                    <span className="font-semibold">{inspectedEvent.event_id}</span>
                    <button onClick={() => setInspectedEvent(null)} className="p-1 rounded hover:opacity-80" style={{ color: 'var(--ink-3)' }}>
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                  <div className="p-3.5 space-y-4 text-xs font-mono">
                    <div className="rounded border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                      <CodeEditor value={inspectedEvent.raw_sql_preview} language="sql" readOnly minRows={3} maxHeightClass="max-h-40" />
                    </div>
                    <dl className="grid grid-cols-2 gap-y-3 gap-x-4 text-[11.5px]">
                      <DetailKV label="Decision" value={inspectedEvent.decision} />
                      <DetailKV label="Profile" value={inspectedEvent.role_profile} />
                      <DetailKV label="Policy Rule" value={inspectedEvent.policy_rule} span2 />
                      <DetailKV label="Statement" value={inspectedEvent.statement_type} />
                      <DetailKV label="Client" value={inspectedEvent.client_addr} />
                      <DetailKV label="Proxy Overhead" value={`${inspectedEvent.proxy_overhead_us} µs`} />
                      <DetailKV label="Upstream PG" value={`${inspectedEvent.upstream_duration_us} µs`} />
                      <DetailKV label="AST Fingerprint" value={inspectedEvent.sql_fingerprint} span2 />
                    </dl>
                    {inspectedEvent.policy_reason && (
                      <div className="pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <div className="text-[10px] uppercase mb-1" style={{ color: 'var(--ink-3)' }}>Reason</div>
                        <div className="font-sans text-xs" style={{ color: 'var(--ink-2)' }}>{inspectedEvent.policy_reason}</div>
                      </div>
                    )}
                    {inspectedEvent.pii_entities && Object.keys(inspectedEvent.pii_entities).length > 0 && (
                      <div className="pt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                        <div className="text-[10px] uppercase mb-1.5" style={{ color: 'var(--ink-3)' }}>Masked PII Breakdown</div>
                        <div className="space-y-1">
                          {Object.entries(inspectedEvent.pii_entities).map(([k, v]) => (
                            <div key={k} className="flex justify-between">
                              <span style={{ color: 'var(--ink-2)' }}>{k}</span>
                              <span style={{ color: 'var(--ok)' }}>{v}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </aside>
              )}
            </div>
          )}

          {/* ========================================================== */}
          {/* VIEW 5: POLICY STUDIO (YAML Hot-Reload)                    */}
          {/* ========================================================== */}
          {tab === 'policies' && (
            <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 min-h-0">
              <div className="lg:col-span-4 border-r overflow-y-auto p-4 space-y-4" style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}>
                <div>
                  <h2 className="text-xs font-semibold uppercase tracking-wider mb-2.5" style={{ color: 'var(--ink-3)' }}>
                    Compliance Packs ({Object.keys(compliancePacks).length})
                  </h2>
                  <div className="divide-y border rounded-md" style={{ borderColor: 'var(--border)' }}>
                    {Object.entries(compliancePacks).map(([pack, entities]) => (
                      <div key={pack} className="p-2.5 space-y-1">
                        <div className="font-mono text-xs font-semibold uppercase">{pack}</div>
                        <div className="font-mono text-[11px] leading-relaxed" style={{ color: 'var(--ink-3)' }}>
                          {entities.join(' · ')}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="lg:col-span-8 flex flex-col min-h-0">
                <div
                  className="shrink-0 border-b px-4 py-2 flex items-center justify-between"
                  style={{ background: 'var(--bg-panel)', borderColor: 'var(--border)' }}
                >
                  <span className="font-mono text-xs" style={{ color: 'var(--ink-2)' }}>
                    configs/pgveil.yaml <span style={{ color: 'var(--ink-3)' }}>· v{policyVersion}</span>
                  </span>
                  <button
                    onClick={savePolicyYAML}
                    disabled={savingPolicy}
                    className="h-7 px-3 rounded-md text-xs font-medium disabled:opacity-50"
                    style={{ background: 'var(--btn-bg)', color: 'var(--btn-fg)' }}
                  >
                    {savingPolicy ? 'Validating…' : 'Validate & Hot-Reload'}
                  </button>
                </div>
                {policyNotice && (
                  <div
                    className="shrink-0 border-b px-4 py-1.5 text-xs font-mono"
                    style={{
                      borderColor: policyNotice.ok ? 'var(--ok-border)' : 'var(--danger-border)',
                      background: policyNotice.ok ? 'var(--ok-subtle)' : 'var(--danger-subtle)',
                      color: policyNotice.ok ? 'var(--ok)' : 'var(--danger)'
                    }}
                  >
                    {policyNotice.msg}
                  </div>
                )}
                <div className="flex-1 min-h-0 overflow-hidden">
                  <CodeEditor
                    value={policyYAML}
                    onChange={setPolicyYAML}
                    language="yaml"
                    minRows={26}
                    maxHeightClass="h-full"
                  />
                </div>
              </div>
            </div>
          )}

          {/* ========================================================== */}
          {/* VIEW 6: CONNECT & TELEMETRY                                */}
          {/* ========================================================== */}
          {tab === 'observability' && (
            <div className="flex-1 overflow-y-auto p-5 space-y-6">
              {/* Crisp Monochrome Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-5 border rounded-md divide-y sm:divide-y-0 sm:divide-x" style={{ borderColor: 'var(--border)', background: 'var(--bg-panel)' }}>
                <MetricCell label="Inspected Queries" value={(summary?.total_queries ?? 0).toLocaleString()} />
                <MetricCell label="PII Cells Masked" value={(summary?.total_pii_fields ?? 0).toLocaleString()} accent="var(--ok)" />
                <MetricCell label="Blocked Attacks" value={(summary?.blocked_queries ?? 0).toLocaleString()} accent={(summary?.blocked_queries ?? 0) > 0 ? 'var(--danger)' : undefined} />
                <MetricCell label="Avg Proxy Overhead" value={`${Math.round(summary?.avg_proxy_overhead_us ?? 0)} µs`} />
                <MetricCell label="Kafka Pipeline" value={summary?.kafka_enabled ? 'ENABLED' : 'LOCAL MODE'} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Masked Entity Distribution */}
                <div className="lg:col-span-5 border rounded-md p-4 space-y-3" style={{ borderColor: 'var(--border)', background: 'var(--bg-panel)' }}>
                  <div className="flex items-center justify-between">
                    <h2 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--ink-3)' }}>
                      Masked PII Distribution
                    </h2>
                    <span className="text-[11px] font-mono" style={{ color: 'var(--ink-3)' }}>
                      proportional
                    </span>
                  </div>
                  {summary && Object.keys(summary.pii_by_entity || {}).length > 0 ? (
                    <div className="space-y-2.5">
                      {Object.entries(summary.pii_by_entity)
                        .sort((a, b) => b[1] - a[1])
                        .map(([ent, count]) => {
                          const maxVal = Math.max(...Object.values(summary.pii_by_entity))
                          const pct = Math.max(1.5, (count / Math.max(1, maxVal)) * 100)
                          return (
                            <div key={ent} className="space-y-1 font-mono text-xs tabular-nums">
                              <div className="flex justify-between">
                                <span style={{ color: 'var(--ink-2)' }}>{ent}</span>
                                <span style={{ color: 'var(--ink-1)' }}>{count.toLocaleString()}</span>
                              </div>
                              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--bg-surface)' }}>
                                <div className="h-full rounded-full" style={{ width: `${pct}%`, background: 'var(--ok)' }} />
                              </div>
                            </div>
                          )
                        })}
                    </div>
                  ) : (
                    <p className="text-xs" style={{ color: 'var(--ink-3)' }}>
                      Execute queries in SQL Workbench to populate entity telemetry.
                    </p>
                  )}
                </div>

                {/* Tabbed Zero-Code Integration Snippets */}
                <div className="lg:col-span-7 border rounded-md overflow-hidden flex flex-col" style={{ borderColor: 'var(--border)', background: 'var(--bg-panel)' }}>
                  <div className="border-b px-2 pt-2 flex items-center justify-between gap-2" style={{ borderColor: 'var(--border)' }}>
                    <div className="flex items-center gap-1 overflow-x-auto">
                      {[
                        { id: 'mcp', label: 'Native MCP' },
                        { id: 'psql', label: 'psql Wire' },
                        { id: 'wire_mcp', label: 'Postgres MCP' },
                        { id: 'python', label: 'Python Agent' },
                        { id: 'helm', label: 'Kubernetes Helm' }
                      ].map((t) => (
                        <button
                          key={t.id}
                          onClick={() => setConnectTab(t.id as typeof connectTab)}
                          className="px-2.5 py-1.5 text-xs font-medium border-b-2 whitespace-nowrap transition-colors"
                          style={{
                            borderColor: connectTab === t.id ? 'var(--ink-1)' : 'transparent',
                            color: connectTab === t.id ? 'var(--ink-1)' : 'var(--ink-3)'
                          }}
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>
                    <button
                      onClick={() => copyText(connectTab, connectSnippets[connectTab].code)}
                      className="mb-1.5 px-2 py-1 rounded border text-[11px] font-mono flex items-center gap-1 shrink-0"
                      style={{ borderColor: 'var(--border)', color: 'var(--ink-2)' }}
                    >
                      {copiedKey === connectTab ? <Check className="w-3 h-3" style={{ color: 'var(--ok)' }} /> : <Copy className="w-3 h-3" />}
                      {copiedKey === connectTab ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="p-3.5 space-y-2.5">
                    <div className="text-xs font-medium">{connectSnippets[connectTab].title}</div>
                    <div className="text-[11.5px]" style={{ color: 'var(--ink-3)' }}>
                      {connectSnippets[connectTab].subtitle}
                    </div>
                    <pre
                      className="p-3 rounded border text-[12px] font-mono overflow-x-auto leading-relaxed"
                      style={{ background: 'var(--bg-canvas)', borderColor: 'var(--border)', color: 'var(--ink-1)' }}
                    >
                      {connectSnippets[connectTab].code}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Cmd+K Command Palette */}
      <CommandPalette
        open={cmdOpen}
        onClose={() => setCmdOpen(false)}
        onNavigate={(nextTab: Tab) => setTab(nextTab)}
        onSelectProfile={setSelectedProfile}
        onRunPreset={(presetSQL) => {
          setSql(presetSQL)
          executeSQL(presetSQL)
        }}
        onTriggerDiscovery={runDiscovery}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        profiles={profiles.map((p) => p.name)}
      />
    </div>
  )
}

function MetricCell({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="px-4 py-3">
      <div className="text-[11px]" style={{ color: 'var(--ink-3)' }}>
        {label}
      </div>
      <div className="text-lg font-semibold font-mono tabular-nums mt-0.5" style={{ color: accent || 'var(--ink-1)' }}>
        {value}
      </div>
    </div>
  )
}

function DetailKV({ label, value, span2 }: { label: string; value: string; span2?: boolean }) {
  return (
    <div className={span2 ? 'col-span-2' : ''}>
      <div className="text-[10px] uppercase" style={{ color: 'var(--ink-3)' }}>
        {label}
      </div>
      <div className={span2 ? 'mt-0.5 break-all' : 'mt-0.5 truncate'} style={{ color: 'var(--ink-1)' }} title={value}>
        {value || '—'}
      </div>
    </div>
  )
}
