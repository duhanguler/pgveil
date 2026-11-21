import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Search, Terminal, ScanSearch, Clock, Activity, Sliders, Cpu, Sun, Moon, Shield, Play } from 'lucide-react'
import { QUERY_PRESETS } from '../data/presets'

export interface CommandItem {
  id: string
  group: string
  label: string
  hint?: string
  icon: React.ReactNode
  action: () => void
}

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
  onNavigate: (tab: any) => void
  onSelectProfile: (profile: string) => void
  onRunPreset: (sql: string) => void
  onTriggerDiscovery: () => void
  theme: 'dark' | 'light'
  onToggleTheme: () => void
  profiles: string[]
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  open,
  onClose,
  onNavigate,
  onSelectProfile,
  onRunPreset,
  onTriggerDiscovery,
  theme,
  onToggleTheme,
  profiles
}) => {
  const [query, setQuery] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const items: CommandItem[] = useMemo(() => {
    const base: CommandItem[] = [
      { id: 'nav-pg', group: 'Navigate', label: 'SQL Workbench', hint: '1', icon: <Terminal className="w-3.5 h-3.5" />, action: () => onNavigate('playground') },
      { id: 'nav-disc', group: 'Navigate', label: 'PII Schema Discovery', hint: '2', icon: <ScanSearch className="w-3.5 h-3.5" />, action: () => onNavigate('discovery') },
      { id: 'nav-hitl', group: 'Navigate', label: 'HITL Approval Queue', hint: '3', icon: <Clock className="w-3.5 h-3.5" />, action: () => onNavigate('approvals') },
      { id: 'nav-audit', group: 'Navigate', label: 'Audit Ledger', hint: '4', icon: <Activity className="w-3.5 h-3.5" />, action: () => onNavigate('audit') },
      { id: 'nav-pol', group: 'Navigate', label: 'Policy Studio (pgveil.yaml)', hint: '5', icon: <Sliders className="w-3.5 h-3.5" />, action: () => onNavigate('policies') },
      { id: 'nav-ops', group: 'Navigate', label: 'Connect & Telemetry', hint: '6', icon: <Cpu className="w-3.5 h-3.5" />, action: () => onNavigate('observability') },
      {
        id: 'act-disc',
        group: 'Actions',
        label: 'Scan Live PostgreSQL Schema for PII',
        hint: 'pgveil discover',
        icon: <ScanSearch className="w-3.5 h-3.5" />,
        action: () => {
          onNavigate('discovery')
          onTriggerDiscovery()
        }
      },
      {
        id: 'act-theme',
        group: 'Actions',
        label: theme === 'dark' ? 'Switch to Swiss Light Theme' : 'Switch to Carbon Dark Theme',
        hint: 'Theme',
        icon: theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />,
        action: onToggleTheme
      }
    ]

    for (const p of profiles) {
      base.push({
        id: `prof-${p}`,
        group: 'Switch Role Profile',
        label: `Use profile: ${p}`,
        hint: 'RBAC',
        icon: <Shield className="w-3.5 h-3.5" />,
        action: () => onSelectProfile(p)
      })
    }

    for (const pr of QUERY_PRESETS) {
      base.push({
        id: `pre-${pr.id}`,
        group: 'Run Scenario',
        label: pr.label,
        hint: pr.category.toUpperCase(),
        icon: <Play className="w-3.5 h-3.5" />,
        action: () => {
          onNavigate('playground')
          onRunPreset(pr.sql)
        }
      })
    }
    return base
  }, [onNavigate, onSelectProfile, onRunPreset, onTriggerDiscovery, onToggleTheme, profiles, theme])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return items
    return items.filter(
      (i) => i.label.toLowerCase().includes(q) || i.group.toLowerCase().includes(q) || (i.hint || '').toLowerCase().includes(q)
    )
  }, [items, query])

  useEffect(() => {
    if (open) {
      setQuery('')
      setActiveIdx(0)
      setTimeout(() => inputRef.current?.focus(), 10)
    }
  }, [open])

  useEffect(() => {
    setActiveIdx(0)
  }, [query])

  if (!open) return null

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[14vh] px-4"
      style={{ background: 'rgba(0,0,0,0.55)', backdropFilter: 'blur(2px)' }}
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-lg border overflow-hidden shadow-2xl"
        style={{ background: 'var(--bg-panel)', borderColor: 'var(--border-strong)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2.5 px-3.5 h-11 border-b" style={{ borderColor: 'var(--border)' }}>
          <Search className="w-4 h-4 shrink-0" style={{ color: 'var(--ink-3)' }} />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') onClose()
              if (e.key === 'ArrowDown') {
                e.preventDefault()
                setActiveIdx((i) => Math.min(filtered.length - 1, i + 1))
              }
              if (e.key === 'ArrowUp') {
                e.preventDefault()
                setActiveIdx((i) => Math.max(0, i - 1))
              }
              if (e.key === 'Enter' && filtered[activeIdx]) {
                e.preventDefault()
                filtered[activeIdx].action()
                onClose()
              }
            }}
            placeholder="Jump to view, switch profile, or run a SQL scenario..."
            className="w-full bg-transparent text-sm focus:outline-none"
            style={{ color: 'var(--ink-1)' }}
          />
          <kbd
            className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
            style={{ borderColor: 'var(--border)', color: 'var(--ink-3)' }}
          >
            ESC
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto py-1.5">
          {filtered.length === 0 ? (
            <div className="px-4 py-6 text-center text-xs" style={{ color: 'var(--ink-3)' }}>
              No matching commands.
            </div>
          ) : (
            filtered.map((item, idx) => {
              const showGroup = idx === 0 || filtered[idx - 1].group !== item.group
              const selected = idx === activeIdx
              return (
                <React.Fragment key={item.id}>
                  {showGroup && (
                    <div
                      className="px-3.5 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider"
                      style={{ color: 'var(--ink-3)' }}
                    >
                      {item.group}
                    </div>
                  )}
                  <button
                    onMouseEnter={() => setActiveIdx(idx)}
                    onClick={() => {
                      item.action()
                      onClose()
                    }}
                    className="w-full px-3.5 py-2 flex items-center justify-between text-xs text-left transition-colors"
                    style={{
                      background: selected ? 'var(--bg-active)' : 'transparent',
                      color: selected ? 'var(--ink-1)' : 'var(--ink-2)'
                    }}
                  >
                    <span className="flex items-center gap-2.5 truncate">
                      <span style={{ color: selected ? 'var(--ink-1)' : 'var(--ink-3)' }}>{item.icon}</span>
                      <span className="truncate">{item.label}</span>
                    </span>
                    {item.hint && (
                      <span className="text-[10px] font-mono ml-3 shrink-0" style={{ color: 'var(--ink-3)' }}>
                        {item.hint}
                      </span>
                    )}
                  </button>
                </React.Fragment>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
