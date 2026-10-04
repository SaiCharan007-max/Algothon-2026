import { Loader2, AlertTriangle } from 'lucide-react'
import { STAGES, SEVERITY_INFO } from '../lib/format'

const SEV_STYLES = {
  critical: 'bg-sev-critical/15 text-sev-critical border-sev-critical/40',
  high: 'bg-sev-high/15 text-sev-high border-sev-high/40',
  medium: 'bg-sev-medium/15 text-sev-medium border-sev-medium/40',
  low: 'bg-sev-low/15 text-sev-low border-sev-low/40',
}

export const SEV_COLOR = {
  critical: '#f43f5e',
  high: '#f97316',
  medium: '#eab308',
  low: '#38bdf8',
}

export function SeverityBadge({ severity, className = '', children }) {
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEV_STYLES[severity] || ''} ${className}`}>
      {children ?? severity}
    </span>
  )
}

// friendly version: "Act now" / "Serious" / "Suspicious" / "Minor"
export function LevelPill({ severity }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${SEV_STYLES[severity] || ''}`}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR[severity] }} />
      {SEVERITY_INFO[severity]?.label || severity}
    </span>
  )
}

export function ScoreBar({ score, severity }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-line">
        <div className="h-full rounded-full" style={{ width: `${score}%`, background: SEV_COLOR[severity] }} />
      </div>
      <span className="mono text-muted">{score}</span>
    </div>
  )
}

export function Chip({ children, onClick, title, tone = 'default' }) {
  const tones = {
    default: 'border-line bg-panel-2 text-slate-300',
    ip: 'border-rose-500/30 bg-rose-500/10 text-rose-200',
    user: 'border-sky-500/30 bg-sky-500/10 text-sky-200',
  }
  const Tag = onClick ? 'button' : 'span'
  return (
    <Tag
      title={title}
      onClick={onClick}
      className={`mono inline-flex items-center gap-1 rounded-md border px-2 py-0.5 ${tones[tone]} ${onClick ? 'hover:brightness-125 cursor-pointer' : ''}`}
    >
      {children}
    </Tag>
  )
}

// the 8 kill-chain stages, highlighting the ones this incident reached
export function StageChain({ stages, compact = false }) {
  const hit = new Set(stages)
  return (
    <div className={`flex flex-wrap items-center ${compact ? 'gap-1' : 'gap-1.5'}`}>
      {STAGES.map((s, i) => (
        <div key={s} className="flex items-center gap-1">
          <span
            title={s}
            className={`rounded px-1.5 py-0.5 ${compact ? 'text-[10px]' : 'text-[11px]'} font-medium ${
              hit.has(s) ? 'bg-rose-500/20 text-rose-200 ring-1 ring-rose-500/40' : 'bg-line/50 text-slate-500'
            }`}
          >
            {compact ? s.split(' ').map((w) => w[0]).join('') : s}
          </span>
          {i < STAGES.length - 1 && !compact && <span className="text-slate-600">›</span>}
        </div>
      ))}
    </div>
  )
}

export function Spinner({ label = 'Loading…' }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-muted">
      <Loader2 className="h-5 w-5 animate-spin" /> {label}
    </div>
  )
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null
  return (
    <div className="flex items-start gap-3 rounded-lg border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-200">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1">{String(error.message || error)}</div>
      {onRetry && (
        <button className="underline" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  )
}

export function StatCard({ label, value, sub, icon: Icon, accent = 'text-slate-100' }) {
  return (
    <div className="panel p-4">
      <div className="flex items-center justify-between text-xs uppercase tracking-wider text-muted">
        {label}
        {Icon && <Icon className="h-4 w-4" />}
      </div>
      <div className={`mt-2 text-2xl font-semibold ${accent}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </div>
  )
}

export function Empty({ children }) {
  return <div className="py-12 text-center text-sm text-muted">{children}</div>
}
