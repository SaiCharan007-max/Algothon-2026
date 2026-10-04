import { useEffect, useLayoutEffect, useMemo, useRef, useState, Fragment } from 'react'
import { Link } from 'react-router-dom'
import { X, ChevronUp, ChevronDown, ArrowRight, FileText, Loader2 } from 'lucide-react'
import { api } from '../api'
import { LevelPill, SEV_COLOR } from './ui'
import { riskText, STAGE_LABELS } from '../lib/format'

const RANK = { low: 1, medium: 2, high: 3, critical: 4 }

// colour a line by the most serious finding it belongs to (matches the verdict cards)
function lineSeverity(alertIds, alerts) {
  let best = null
  for (const id of alertIds) {
    const sev = alerts[id]?.incident_severity || alerts[id]?.severity
    if (!best || RANK[sev] > RANK[best]) best = sev
  }
  return best
}

const keyOf = (file, seq) => `${file}#${seq}`

function Explanation({ uploadId, alertIds, alerts, onClose, onPrev, onNext, position }) {
  const list = alertIds.map((id) => alerts[id]).filter(Boolean)
  return (
    <div className="relative rounded-xl border border-slate-600 bg-panel-2 p-4 shadow-2xl shadow-black/50">
      {/* the arrow pointing back at the log line */}
      <span className="absolute -left-[7px] top-5 hidden h-3.5 w-3.5 rotate-45 border-b border-l border-slate-600 bg-panel-2 lg:block" />
      <span className="absolute -top-[7px] left-8 h-3.5 w-3.5 rotate-45 border-l border-t border-slate-600 bg-panel-2 lg:hidden" />

      <div className="mb-3 flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-muted">Why this line is suspicious</span>
        <button onClick={onClose} className="text-slate-500 hover:text-white" title="Close">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-4">
        {list.map((a) => (
          <div key={a.id}>
            <div className="flex flex-wrap items-center gap-2">
              <LevelPill severity={a.incident_severity || a.severity} />
              <span className="text-xs text-muted">{STAGE_LABELS[a.stage]}</span>
            </div>
            <div className="mt-2 font-medium leading-snug text-white">{a.title}</div>
            <p className="mt-1.5 text-[13px] leading-relaxed text-slate-400">{a.description}</p>
            <div className="mt-3 rounded-lg border border-line bg-black/20 p-3">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-rose-300">The risk</div>
              <p className="mt-1 text-[13px] leading-relaxed text-slate-200">{riskText(a)}</p>
            </div>
            {a.incident_ref && (
              <Link
                to={`/analysis/${uploadId}/incident/${a.incident_ref}`}
                className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-sky-300 hover:text-sky-200"
              >
                {a.steps > 1 ? `Step ${a.step} of ${a.steps} in "${a.incident_title}"` : 'Open this finding'} <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        ))}
      </div>

      <div className="mt-4 flex items-center justify-between border-t border-line pt-3 text-xs text-muted">
        <span>
          Suspicious line {position.index + 1} of {position.total}
        </span>
        <div className="flex gap-1">
          <button className="btn-ghost px-2 py-1" onClick={onPrev} disabled={position.index === 0} title="Previous suspicious line">
            <ChevronUp className="h-4 w-4" />
          </button>
          <button className="btn-ghost px-2 py-1" onClick={onNext} disabled={position.index >= position.total - 1} title="Next suspicious line">
            <ChevronDown className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default function LogViewer({ uploadId, data }) {
  const [files, setFiles] = useState(data.files)
  const [selected, setSelected] = useState(null) // key of selected line
  const [popupTop, setPopupTop] = useState(0)
  const [popupHeight, setPopupHeight] = useState(0)
  const [loadingGap, setLoadingGap] = useState(null)
  const autoPicked = useRef(false)
  const popupRef = useRef(null)
  const rowRefs = useRef(new Map())
  const wrapRefs = useRef(new Map())

  useEffect(() => setFiles(data.files), [data])

  // every flagged line in reading order, for prev / next
  const flagged = useMemo(
    () => files.flatMap((f) => f.items.filter((it) => it.type === 'line' && it.alerts.length).map((it) => ({ file: f.name, item: it, key: keyOf(f.name, it.seq) }))),
    [files],
  )

  // start with the first line of the most serious finding, so the popup is visible straight away
  useEffect(() => {
    if (autoPicked.current || !flagged.length) return
    autoPicked.current = true
    let best = flagged[0]
    for (const f of flagged) {
      if (RANK[lineSeverity(f.item.alerts, data.alerts)] > RANK[lineSeverity(best.item.alerts, data.alerts)]) best = f
    }
    setSelected(best.key)
  }, [flagged, data.alerts])

  const current = flagged.find((f) => f.key === selected)
  const index = flagged.findIndex((f) => f.key === selected)

  // line the popup up with the selected row (desktop). Re-measure whenever the
  // file box changes size, because long lines re-wrap at different widths.
  useLayoutEffect(() => {
    if (!current) return
    const row = rowRefs.current.get(current.key)
    const wrap = wrapRefs.current.get(current.file)
    if (!row || !wrap) return
    const measure = () => setPopupTop(row.getBoundingClientRect().top - wrap.getBoundingClientRect().top - 8)
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(wrap)
    return () => ro.disconnect()
  }, [current, files])

  // remember the popup height so the file box grows instead of clipping it
  useLayoutEffect(() => {
    const h = popupRef.current?.offsetHeight || 0
    if (h !== popupHeight) setPopupHeight(h)
  })

  const go = (i) => {
    const target = flagged[i]
    if (!target) return
    setSelected(target.key)
    rowRefs.current.get(target.key)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }

  const expandGap = async (fileName, gap) => {
    setLoadingGap(`${fileName}:${gap.fromLine}`)
    try {
      const lines = await api.lines(uploadId, fileName, gap.fromLine, gap.toLine)
      setFiles((prev) =>
        prev.map((f) => {
          if (f.name !== fileName) return f
          const items = []
          for (const it of f.items) {
            if (it !== gap) {
              items.push(it)
              continue
            }
            items.push(...lines)
            const shown = lines.length
            if (shown < gap.count) {
              const last = lines[lines.length - 1]?.line ?? gap.fromLine - 1
              items.push({ type: 'gap', count: gap.count - shown, fromLine: last + 1, toLine: gap.toLine })
            }
          }
          return { ...f, items }
        }),
      )
    } finally {
      setLoadingGap(null)
    }
  }

  return (
    <div className="space-y-6">
      {files.map((f) => (
        <div key={f.name} className="panel">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line px-4 py-3">
            <FileText className="h-4 w-4 text-slate-400" />
            <span className="mono text-sm text-slate-100">{f.name}</span>
            <span className="text-xs text-muted">
              {f.totalLines.toLocaleString()} lines ·{' '}
              {f.flaggedLines ? <span className="text-rose-300">{f.flaggedLines} suspicious</span> : <span className="text-emerald-300">nothing suspicious</span>}
            </span>
          </div>

          <div
            className="relative lg:pr-[372px]"
            ref={(el) => (el ? wrapRefs.current.set(f.name, el) : wrapRefs.current.delete(f.name))}
            style={{ minHeight: current?.file === f.name ? Math.max(8, popupTop) + popupHeight + 16 : undefined }}
          >
            <div className="py-2">
              {f.items.map((it, i) => {
                if (it.type === 'gap') {
                  const loading = loadingGap === `${f.name}:${it.fromLine}`
                  return (
                    <button
                      key={`gap-${it.fromLine}-${i}`}
                      onClick={() => expandGap(f.name, it)}
                      disabled={loading}
                      className="my-1 flex w-full items-center gap-3 px-4 py-1.5 text-left text-xs text-slate-500 hover:bg-panel-2/60 hover:text-slate-300"
                    >
                      <span className="w-10 text-right">⋯</span>
                      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                      {it.count.toLocaleString()} normal line{it.count === 1 ? '' : 's'} hidden (lines {it.fromLine}–{it.toLine}). Click to show
                    </button>
                  )
                }

                const key = keyOf(f.name, it.seq)
                const sev = it.alerts.length ? lineSeverity(it.alerts, data.alerts) : null
                const isSel = key === selected
                return (
                  <Fragment key={key}>
                    <div
                      ref={(el) => (el ? rowRefs.current.set(key, el) : rowRefs.current.delete(key))}
                      onClick={() => sev && setSelected(isSel ? null : key)}
                      className={`flex gap-3 px-4 py-[3px] ${sev ? 'cursor-pointer hover:bg-panel-2/80' : ''} ${isSel ? 'bg-panel-2' : ''}`}
                      style={isSel ? { boxShadow: `inset 3px 0 0 ${SEV_COLOR[sev]}` } : undefined}
                    >
                      <span className="mono w-10 shrink-0 select-none text-right text-slate-600">{it.line}</span>
                      <span
                        className={`mono min-w-0 flex-1 whitespace-pre-wrap break-all ${sev ? 'text-slate-100' : 'text-slate-500'}`}
                        style={
                          sev
                            ? {
                                textDecorationLine: 'underline',
                                textDecorationStyle: 'wavy',
                                textDecorationColor: SEV_COLOR[sev],
                                textDecorationThickness: '1.5px',
                                textUnderlineOffset: '4px',
                              }
                            : undefined
                        }
                      >
                        {it.raw}
                      </span>
                    </div>
                    {/* phones / small screens: explanation opens right under the line */}
                    {isSel && (
                      <div className="px-4 py-3 lg:hidden">
                        <Explanation
                          uploadId={uploadId}
                          alertIds={it.alerts}
                          alerts={data.alerts}
                          onClose={() => setSelected(null)}
                          onPrev={() => go(index - 1)}
                          onNext={() => go(index + 1)}
                          position={{ index, total: flagged.length }}
                        />
                      </div>
                    )}
                  </Fragment>
                )
              })}
            </div>

            {/* desktop: explanation floats beside the selected line, arrow pointing at it */}
            {current?.file === f.name && (
              <div ref={popupRef} className="absolute right-3 hidden w-[350px] transition-[top] duration-200 lg:block" style={{ top: Math.max(8, popupTop) }}>
                <Explanation
                  uploadId={uploadId}
                  alertIds={current.item.alerts}
                  alerts={data.alerts}
                  onClose={() => setSelected(null)}
                  onPrev={() => go(index - 1)}
                  onNext={() => go(index + 1)}
                  position={{ index, total: flagged.length }}
                />
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
