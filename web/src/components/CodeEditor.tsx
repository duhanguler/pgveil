import React, { useMemo, useRef } from 'react'

interface CodeEditorProps {
  value: string
  onChange?: (val: string) => void
  language: 'sql' | 'yaml'
  readOnly?: boolean
  minRows?: number
  maxHeightClass?: string
  onRunShortcut?: () => void
  placeholder?: string
}

const SQL_KEYWORDS = new Set([
  'SELECT', 'FROM', 'WHERE', 'ORDER', 'BY', 'LIMIT', 'OFFSET', 'GROUP', 'HAVING',
  'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON', 'AS', 'AND', 'OR', 'NOT',
  'IN', 'IS', 'NULL', 'TRUE', 'FALSE', 'LIKE', 'ILIKE', 'BETWEEN', 'CASE', 'WHEN',
  'THEN', 'ELSE', 'END', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE',
  'DROP', 'TABLE', 'TRUNCATE', 'ALTER', 'CREATE', 'WITH', 'RETURNING', 'EXPLAIN',
  'SHOW', 'COPY', 'PROGRAM', 'DO', 'BEGIN', 'COMMIT', 'ROLLBACK', 'ASC', 'DESC',
  'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'SUBSTRING', 'COALESCE'
])

function escapeHTML(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

function highlightSQL(code: string): string {
  // Single-pass regex tokenizer for comments, single-quoted strings, numbers, and identifiers/keywords
  const re = /(--[^\n]*)|('(?:''|[^'])*')|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_][A-Za-z0-9_]*\b)/g
  let out = ''
  let last = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(code)) !== null) {
    out += escapeHTML(code.slice(last, m.index))
    const [full, comment, str, num, ident] = m
    if (comment) {
      out += `<span style="color:var(--syn-cmt)">${escapeHTML(full)}</span>`
    } else if (str) {
      out += `<span style="color:var(--syn-str)">${escapeHTML(full)}</span>`
    } else if (num) {
      out += `<span style="color:var(--syn-num)">${escapeHTML(full)}</span>`
    } else if (ident && SQL_KEYWORDS.has(ident.toUpperCase())) {
      out += `<span style="color:var(--syn-kw);font-weight:500">${escapeHTML(full)}</span>`
    } else {
      out += escapeHTML(full)
    }
    last = m.index + full.length
  }
  out += escapeHTML(code.slice(last))
  // Keep trailing newline height synced with textarea
  return out.endsWith('\n') ? out + ' ' : out
}

function highlightYAML(code: string): string {
  return code
    .split('\n')
    .map((line) => {
      const trimmed = line.trimStart()
      if (trimmed.startsWith('#')) {
        return `<span style="color:var(--syn-cmt)">${escapeHTML(line)}</span>`
      }
      const keyMatch = line.match(/^(\s*-?\s*)([A-Za-z0-9_.-]+)(:)(\s*)(.*)$/)
      if (keyMatch) {
        const [, indent, key, colon, space, rest] = keyMatch
        let valHTML = escapeHTML(rest)
        if (rest.startsWith('"') || rest.startsWith("'")) {
          valHTML = `<span style="color:var(--syn-str)">${escapeHTML(rest)}</span>`
        } else if (/^(true|false|null)$/i.test(rest.trim())) {
          valHTML = `<span style="color:var(--syn-kw)">${escapeHTML(rest)}</span>`
        } else if (/^\d+(\.\d+)?$/.test(rest.trim())) {
          valHTML = `<span style="color:var(--syn-num)">${escapeHTML(rest)}</span>`
        } else if (rest.includes('#')) {
          const hashIdx = rest.indexOf('#')
          valHTML =
            escapeHTML(rest.slice(0, hashIdx)) +
            `<span style="color:var(--syn-cmt)">${escapeHTML(rest.slice(hashIdx))}</span>`
        }
        return `${escapeHTML(indent)}<span style="color:var(--syn-key)">${escapeHTML(key)}</span>${colon}${space}${valHTML}`
      }
      if (trimmed.startsWith('- ')) {
        const idx = line.indexOf('- ')
        return `${escapeHTML(line.slice(0, idx + 2))}<span style="color:var(--syn-str)">${escapeHTML(line.slice(idx + 2))}</span>`
      }
      return escapeHTML(line)
    })
    .join('\n')
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  value,
  onChange,
  language,
  readOnly = false,
  minRows = 5,
  maxHeightClass = 'max-h-[260px]',
  onRunShortcut,
  placeholder
}) => {
  const preRef = useRef<HTMLPreElement>(null)
  const gutterRef = useRef<HTMLDivElement>(null)

  const lines = useMemo(() => Math.max(minRows, value.split('\n').length), [value, minRows])
  const highlighted = useMemo(
    () => (language === 'sql' ? highlightSQL(value) : highlightYAML(value)),
    [value, language]
  )

  const handleScroll = (e: React.UIEvent<HTMLElement>) => {
    const top = e.currentTarget.scrollTop
    const left = e.currentTarget.scrollLeft
    if (preRef.current && e.currentTarget !== preRef.current) {
      preRef.current.scrollTop = top
      preRef.current.scrollLeft = left
    }
    if (gutterRef.current) {
      gutterRef.current.scrollTop = top
    }
  }

  return (
    <div
      className={`relative flex font-mono text-[12.5px] leading-[21px] overflow-hidden ${maxHeightClass}`}
      style={{ background: 'var(--bg-canvas)' }}
    >
      {/* Line Number Gutter */}
      <div
        ref={gutterRef}
        aria-hidden="true"
        className="select-none py-3 px-2.5 text-right tabular-nums overflow-hidden shrink-0 border-r"
        style={{
          color: 'var(--ink-3)',
          background: 'var(--bg-panel)',
          borderColor: 'var(--border)',
          minWidth: '40px'
        }}
      >
        {Array.from({ length: lines }, (_, i) => (
          <div key={i}>{i + 1}</div>
        ))}
      </div>

      {/* Synchronized Highlight Layer + Editable Textarea */}
      <div className="relative flex-1 overflow-hidden" style={{ minHeight: `${minRows * 21 + 24}px` }}>
        <pre
          ref={preRef}
          onScroll={readOnly ? handleScroll : undefined}
          className={`m-0 py-3 px-3.5 whitespace-pre h-full ${readOnly ? 'overflow-auto' : 'overflow-hidden pointer-events-none'}`}
          style={{ color: 'var(--ink-1)' }}
          dangerouslySetInnerHTML={{
            __html: value ? highlighted : `<span style="color:var(--ink-3)">${escapeHTML(placeholder || '')}</span>`
          }}
        />
        {!readOnly && (
          <textarea
            value={value}
            onChange={(e) => onChange?.(e.target.value)}
            onScroll={handleScroll}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && onRunShortcut) {
                e.preventDefault()
                onRunShortcut()
              }
            }}
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            autoCorrect="off"
            className="absolute inset-0 w-full h-full py-3 px-3.5 bg-transparent text-transparent resize-none focus:outline-none whitespace-pre overflow-auto"
            style={{ caretColor: 'var(--ink-1)' }}
          />
        )}
      </div>
    </div>
  )
}
