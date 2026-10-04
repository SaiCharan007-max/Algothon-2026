import { useState, Fragment } from 'react'
import { ChevronRight } from 'lucide-react'
import { fmtTime, fmtBytes } from '../lib/format'

function summary(e) {
  if (e.source === 'web' || e.path) {
    return `${e.method || ''} ${e.path || ''} → ${e.status_code ?? '?'}${e.bytes ? ` (${fmtBytes(e.bytes)})` : ''}`
  }
  if (e.action === 'login') return `${e.outcome === 'success' ? 'login OK' : 'login FAILED'}${e.detail ? ` · ${e.detail}` : ''}`
  return e.detail || e.action
}

export default function EventsTable({ events, highlight = new Set(), onFilter }) {
  const [open, setOpen] = useState(null)

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-sm">
        <thead className="text-left text-xs uppercase tracking-wider text-muted">
          <tr className="border-b border-line">
            <th className="w-6" />
            <th className="px-3 py-2 font-medium">Time (UTC)</th>
            <th className="px-3 py-2 font-medium">Source</th>
            <th className="px-3 py-2 font-medium">IP</th>
            <th className="px-3 py-2 font-medium">User</th>
            <th className="px-3 py-2 font-medium">What happened</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => {
            const failed = e.outcome === 'failure'
            const isOpen = open === e.seq
            return (
              <Fragment key={e.seq}>
                <tr
                  onClick={() => setOpen(isOpen ? null : e.seq)}
                  className={`cursor-pointer border-b border-line/50 hover:bg-panel-2/70 ${highlight.has(e.seq) ? 'bg-rose-500/5' : ''}`}
                >
                  <td className="pl-2 text-slate-500">
                    <ChevronRight className={`h-3.5 w-3.5 transition ${isOpen ? 'rotate-90' : ''}`} />
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 mono text-slate-400">{fmtTime(e.ts)}</td>
                  <td className="px-3 py-1.5">
                    <span className="mono rounded bg-line/60 px-1.5 py-0.5 text-slate-300">{e.source}</span>
                  </td>
                  <td className="px-3 py-1.5 mono">
                    {e.ip ? (
                      <button className="hover:text-rose-300" onClick={(ev) => (ev.stopPropagation(), onFilter?.({ ip: e.ip }))}>
                        {e.ip}
                      </button>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-3 py-1.5 mono">
                    {e.username ? (
                      <button className="hover:text-sky-300" onClick={(ev) => (ev.stopPropagation(), onFilter?.({ user: e.username }))}>
                        {e.username}
                      </button>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className={`max-w-[520px] truncate px-3 py-1.5 mono ${failed ? 'text-amber-300' : 'text-slate-300'}`}>{summary(e)}</td>
                </tr>
                {isOpen && (
                  <tr className="border-b border-line/50 bg-black/30">
                    <td />
                    <td colSpan={5} className="px-3 py-2">
                      <div className="mb-1 text-[11px] text-muted">
                        {e.file}:{e.line_no}
                      </div>
                      <pre className="mono whitespace-pre-wrap break-all text-emerald-200/90">{e.raw}</pre>
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

