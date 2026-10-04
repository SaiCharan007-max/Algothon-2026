import { useEffect, useState, useCallback } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { ArrowLeft, ArrowDown, ChevronRight, ChevronDown, Search, ShieldAlert, ShieldCheck, ShieldQuestion, Wrench, Target, CircleCheck, CircleX, Info } from 'lucide-react'
import { api } from '../api'
import { SeverityBadge, ScoreBar, Chip, Spinner, ErrorBox, StatCard, Empty, LevelPill, SEV_COLOR } from '../components/ui'
import ActivityChart from '../components/ActivityChart'
import LogViewer from '../components/LogViewer'
import EventsTable from '../components/EventsTable'
import { fmtTime, fmtDuration, fmtNum, RULE_LABELS, STAGE_LABELS } from '../lib/format'

const TABS = [
  { id: 'chart', label: 'Activity chart' },
  { id: 'entities', label: 'Flagged IPs & users' },
  { id: 'alerts', label: 'All alerts' },
  { id: 'events', label: 'Search log lines' },
]

function Verdict({ incidents }) {
  const attacks = incidents.filter((i) => i.severity === 'critical' || i.severity === 'high')
  const suspicious = incidents.filter((i) => i.severity === 'medium')

  if (attacks.length) {
    const top = attacks[0]
    const brokeIn = top.stages.includes('Initial Access')
    return (
      <div className="flex items-start gap-4 rounded-xl border border-sev-critical/40 bg-sev-critical/10 p-5">
        <ShieldAlert className="mt-0.5 h-8 w-8 shrink-0 text-sev-critical" />
        <div>
          <div className="text-xl font-semibold text-white">
            {brokeIn ? 'Someone broke in.' : `We found ${attacks.length === 1 ? 'an attack' : `${attacks.length} attacks`}.`}
          </div>
          <p className="mt-1 text-slate-300">
            {brokeIn
              ? `The attacker came from ${top.ips[0]} and got into ${top.users.length ? top.users.join(' and ') : 'an account'}. Open the first item below to see exactly what they did.`
              : 'It doesn\'t look like they got in, but open the items below to check.'}
          </p>
        </div>
      </div>
    )
  }
  if (suspicious.length) {
    return (
      <div className="flex items-start gap-4 rounded-xl border border-sev-medium/40 bg-sev-medium/10 p-5">
        <ShieldQuestion className="mt-0.5 h-8 w-8 shrink-0 text-sev-medium" />
        <div>
          <div className="text-xl font-semibold text-white">Nothing confirmed, but a few things look odd.</div>
          <p className="mt-1 text-slate-300">Have a quick look at the items below.</p>
        </div>
      </div>
    )
  }
  return (
    <div className="flex items-start gap-4 rounded-xl border border-emerald-500/40 bg-emerald-500/10 p-5">
      <ShieldCheck className="mt-0.5 h-8 w-8 shrink-0 text-emerald-400" />
      <div>
        <div className="text-xl font-semibold text-white">No signs of an attack.</div>
        <p className="mt-1 text-slate-300">{incidents.length ? 'Only a few minor things, listed below.' : 'Nothing in these logs matched any of our checks.'}</p>
      </div>
    </div>
  )
}

// only shown for our sample files, where every line's true answer is known
function AccuracyPanel({ ev }) {
  const pct = (a, b) => (b ? Math.round((a / b) * 100) : 100)
  const rows = []
  if (ev.attack.total) {
    rows.push({
      ok: ev.attack.caught === ev.attack.total,
      big: `${ev.attack.caught}/${ev.attack.total}`,
      text: `lines of the planted break-in were flagged (${pct(ev.attack.caught, ev.attack.total)}%)`,
    })
  }
  if (ev.attempt.total) {
    rows.push({ ok: ev.attempt.caught === ev.attempt.total, big: `${ev.attempt.caught}/${ev.attempt.total}`, text: 'lines of the failed password-guessing attempt were flagged' })
  }
  rows.push({
    ok: ev.normal.falseAlarms === 0,
    big: `${ev.normal.falseAlarms}`,
    text: `false alarms on ${fmtNum(ev.normal.total)} normal lines${ev.normal.minorNotes ? ` (${ev.normal.minorNotes} minor notes)` : ''}`,
  })
  if (ev.odd.total) {
    rows.push({ ok: true, neutral: true, big: `${ev.odd.flagged}/${ev.odd.total}`, text: 'harmless-but-unusual lines shown as "Minor", for a human to glance at' })
  }

  return (
    <div className="panel p-4">
      <div className="flex items-center gap-2 font-semibold text-white">
        <Target className="h-4 w-4 text-sky-300" /> How accurate was this?
      </div>
      <p className="mt-1 text-xs text-muted">This is one of our sample files, so we know the true answer for every line. Here is LogHound's score against it.</p>
      <ul className="mt-3 grid gap-2 sm:grid-cols-2">
        {rows.map((r, i) => (
          <li key={i} className="flex items-center gap-3 rounded-lg bg-panel-2 px-3 py-2">
            {r.neutral ? <Info className="h-5 w-5 shrink-0 text-slate-400" /> : r.ok ? <CircleCheck className="h-5 w-5 shrink-0 text-emerald-400" /> : <CircleX className="h-5 w-5 shrink-0 text-sev-high" />}
            <span className="text-lg font-semibold text-white">{r.big}</span>
            <span className="text-sm text-slate-400">{r.text}</span>
          </li>
        ))}
      </ul>
      {ev.attack.missed?.length > 0 && (
        <div className="mt-3 text-xs text-muted">
          Missed:{' '}
          {ev.attack.missed.map((m) => (
            <div key={`${m.file}${m.line}`} className="mono mt-1 truncate text-slate-400">
              {m.file}:{m.line} {m.raw}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FindingCard({ id, inc }) {
  return (
    <Link
      to={`/analysis/${id}/incident/${inc.ref}`}
      className="panel group block p-4 transition hover:border-slate-500"
      style={{ borderLeft: `4px solid ${SEV_COLOR[inc.severity]}` }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <LevelPill severity={inc.severity} />
        <span className="text-xs text-muted">{fmtTime(inc.first_seen, { seconds: false })} UTC</span>
      </div>
      <div className="mt-2 text-lg font-medium text-white">{inc.title}</div>
      <p className="mt-1 text-sm leading-relaxed text-slate-400">{inc.story.summary}</p>
      {inc.stages.length > 1 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {inc.stages.map((s, i) => (
            <span key={s} className="text-xs text-slate-300">
              <span className="rounded bg-line/70 px-1.5 py-0.5">{STAGE_LABELS[s]}</span>
              {i < inc.stages.length - 1 && <span className="ml-1.5 text-slate-600">→</span>}
            </span>
          ))}
        </div>
      )}
      <div className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-rose-300 group-hover:text-rose-200">
        See what happened <ChevronRight className="h-4 w-4 transition group-hover:translate-x-0.5" />
      </div>
    </Link>
  )
}

export default function Analysis() {
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab')
  const [showDetails, setShowDetails] = useState(!!tab)
  const [showMinor, setShowMinor] = useState(false)
  const [data, setData] = useState(null)
  const [annotated, setAnnotated] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(() => {
    setError(null)
    Promise.all([api.getUpload(id), api.annotated(id)])
      .then(([upload, ann]) => {
        setData(upload)
        setAnnotated(ann)
      })
      .catch(setError)
  }, [id])
  useEffect(load, [load])
  useEffect(() => {
    if (tab) setShowDetails(true)
  }, [tab])

  const setTab = (t, extra = {}) => setParams({ tab: t, ...extra })

  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!data || !annotated) return <Spinner label="Checking results…" />

  const { stats, histogram, entities } = data.summary
  const major = data.incidents.filter((i) => i.severity !== 'low')
  const minor = data.incidents.filter((i) => i.severity === 'low')
  const activeTab = tab || 'chart'

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <Link to="/" className="mb-3 inline-flex items-center gap-1 text-sm text-muted hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Check other logs
        </Link>
        <h1 className="text-xl font-semibold text-white">{data.name}</h1>
        <div className="mt-1 text-sm text-muted">
          We checked {fmtNum(stats.events)} log lines from {fmtTime(stats.firstEvent, { seconds: false })} to {fmtTime(stats.lastEvent, { seconds: false })} UTC.
        </div>
      </div>

      <section>
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Your logs, line by line</h2>
            <p className="mt-0.5 text-sm text-muted">
              Suspicious lines have a wavy underline (
              <span className="text-sev-critical">red</span> = act now, <span className="text-sev-high">orange</span> = serious,{' '}
              <span className="text-sev-medium">yellow</span> = suspicious, <span className="text-sev-low">blue</span> = minor). Click one to see why.
            </p>
          </div>
          <a href="#verdict" className="btn-ghost">
            Jump to verdict <ArrowDown className="h-4 w-4" />
          </a>
        </div>
        <LogViewer uploadId={id} data={annotated} />
      </section>

      <section id="verdict" className="scroll-mt-20 space-y-3 border-t border-line pt-6">
        <h2 className="text-lg font-semibold text-white">Verdict</h2>
        <Verdict incidents={data.incidents} />
        {data.summary.evaluation && <AccuracyPanel ev={data.summary.evaluation} />}
      </section>

      {major.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-medium text-muted">What we found ({major.length})</h2>
          {major.map((inc) => (
            <FindingCard key={inc.id} id={id} inc={inc} />
          ))}
        </section>
      )}

      {minor.length > 0 && (
        <section>
          <button className="inline-flex items-center gap-1 text-sm text-muted hover:text-slate-200" onClick={() => setShowMinor((v) => !v)}>
            <ChevronDown className={`h-4 w-4 transition ${showMinor ? 'rotate-180' : ''}`} />
            {minor.length} minor thing{minor.length > 1 ? 's' : ''} (probably harmless)
          </button>
          {showMinor && (
            <div className="mt-3 space-y-3">
              {minor.map((inc) => (
                <FindingCard key={inc.id} id={id} inc={inc} />
              ))}
            </div>
          )}
        </section>
      )}

      <section className="border-t border-line pt-5">
        <button
          className="inline-flex items-center gap-2 text-sm text-muted hover:text-slate-200"
          onClick={() => {
            setShowDetails((v) => !v)
            if (showDetails && tab) setParams({})
          }}
        >
          <Wrench className="h-4 w-4" />
          {showDetails ? 'Hide technical details' : 'Show technical details'}
          <ChevronDown className={`h-4 w-4 transition ${showDetails ? 'rotate-180' : ''}`} />
        </button>

        {showDetails && (
          <div className="mt-4 space-y-4">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <StatCard label="Log lines" value={fmtNum(stats.events)} sub={`${fmtNum(stats.uniqueIps)} IPs · ${fmtNum(stats.uniqueUsers)} users`} />
              <StatCard label="Alerts" value={stats.alerts} sub="from 9 detection rules" />
              <StatCard label="Flagged" value={entities.length} sub="IPs and accounts" />
              <StatCard label="Failed logins" value={fmtNum(stats.failedLogins)} sub={`${fmtNum(stats.successfulLogins)} successful`} />
            </div>
            <div className="text-xs text-muted">
              Files:{' '}
              {data.files.map((f) => `${f.name} (${f.format}, ${fmtNum(f.parsed)} lines read${f.skipped ? `, ${f.skipped} skipped` : ''})`).join(' · ')}
            </div>

            <div className="flex gap-1 overflow-x-auto border-b border-line">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`whitespace-nowrap border-b-2 px-3 py-2 text-sm transition ${
                    activeTab === t.id ? 'border-rose-400 text-white' : 'border-transparent text-muted hover:text-slate-200'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {activeTab === 'chart' && (
              <div className="panel p-4">
                <ActivityChart histogram={histogram} />
              </div>
            )}
            {activeTab === 'entities' && <Entities entities={entities} onPick={(f) => setTab('events', f)} />}
            {activeTab === 'alerts' && <Alerts id={id} alerts={data.alerts} />}
            {activeTab === 'events' && <Explorer id={id} params={params} setParams={setParams} />}
          </div>
        )}
      </section>
    </div>
  )
}

function Entities({ entities, onPick }) {
  if (!entities.length) return <Empty>No suspicious IPs or users.</Empty>
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full min-w-[720px] text-sm">
        <thead className="text-left text-xs uppercase tracking-wider text-muted">
          <tr className="border-b border-line">
            <th className="px-4 py-3 font-medium">Entity</th>
            <th className="px-4 py-3 font-medium">Risk</th>
            <th className="px-4 py-3 font-medium">Why it was flagged</th>
            <th className="px-4 py-3 font-medium">Incident</th>
            <th className="px-4 py-3 font-medium">Events</th>
            <th className="px-4 py-3 font-medium">Active (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {entities.map((e) => {
            const sev = e.risk >= 80 ? 'critical' : e.risk >= 50 ? 'high' : e.risk >= 25 ? 'medium' : 'low'
            return (
              <tr key={`${e.type}:${e.value}`} className="border-b border-line/60 last:border-0 hover:bg-panel-2/60">
                <td className="px-4 py-3">
                  <Chip tone={e.type} onClick={() => onPick(e.type === 'ip' ? { ip: e.value } : { user: e.value })} title="Show this entity's events">
                    {e.type === 'ip' ? 'IP' : 'user'} · {e.value}
                  </Chip>
                </td>
                <td className="px-4 py-3">
                  <ScoreBar score={e.risk} severity={sev} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {e.rules.map((r) => (
                      <span key={r} className="rounded bg-line/60 px-1.5 py-0.5 text-[11px] text-slate-300">
                        {RULE_LABELS[r] || r}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3 mono text-muted">{e.incidents.join(', ')}</td>
                <td className="px-4 py-3 mono">{fmtNum(e.events)}</td>
                <td className="px-4 py-3 text-xs text-muted">
                  {fmtTime(e.firstSeen, { seconds: false })} → {fmtTime(e.lastSeen, { seconds: false })}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function Alerts({ id, alerts }) {
  if (!alerts.length) return <Empty>No alerts.</Empty>
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full min-w-[760px] text-sm">
        <thead className="text-left text-xs uppercase tracking-wider text-muted">
          <tr className="border-b border-line">
            <th className="px-4 py-3 font-medium">Time (UTC)</th>
            <th className="px-4 py-3 font-medium">Severity</th>
            <th className="px-4 py-3 font-medium">Rule / stage</th>
            <th className="px-4 py-3 font-medium">Details</th>
            <th className="px-4 py-3 font-medium">Incident</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id} className="border-b border-line/60 align-top last:border-0">
              <td className="whitespace-nowrap px-4 py-3 mono text-slate-400">{fmtTime(a.first_seen)}</td>
              <td className="px-4 py-3">
                <SeverityBadge severity={a.severity} />
              </td>
              <td className="px-4 py-3">
                <div className="text-slate-200">{RULE_LABELS[a.rule] || a.rule}</div>
                <div className="text-xs text-muted">{a.stage}</div>
              </td>
              <td className="px-4 py-3">
                <div className="font-medium text-slate-200">{a.title}</div>
                <div className="mt-0.5 text-xs text-muted">{a.description}</div>
              </td>
              <td className="px-4 py-3">
                {a.incident_ref && (
                  <Link to={`/analysis/${id}/incident/${a.incident_ref}`} className="mono text-rose-300 hover:underline">
                    {a.incident_ref}
                  </Link>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const PAGE = 100

function Explorer({ id, params, setParams }) {
  const filters = {
    ip: params.get('ip') || '',
    user: params.get('user') || '',
    source: params.get('source') || '',
    outcome: params.get('outcome') || '',
    q: params.get('q') || '',
  }
  const page = Number(params.get('page') || 0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [draft, setDraft] = useState(filters)
  const key = JSON.stringify({ ...filters, page })

  useEffect(() => {
    let alive = true
    setResult(null)
    api
      .events(id, { ...JSON.parse(key), limit: PAGE, offset: page * PAGE })
      .then((r) => alive && setResult(r))
      .catch((e) => alive && setError(e))
    return () => {
      alive = false
    }
  }, [id, key, page])

  useEffect(() => setDraft(filters), [key]) // eslint-disable-line react-hooks/exhaustive-deps

  const apply = (next) => {
    const clean = Object.fromEntries(Object.entries({ ...next }).filter(([k, v]) => v && k !== 'page'))
    setParams({ tab: 'events', ...clean })
  }

  return (
    <div className="space-y-3">
      <form
        className="panel grid gap-2 p-3 sm:grid-cols-2 xl:grid-cols-[1fr_1fr_auto_auto_2fr_auto]"
        onSubmit={(e) => {
          e.preventDefault()
          apply(draft)
        }}
      >
        <input className="input mono" placeholder="IP address" value={draft.ip} onChange={(e) => setDraft({ ...draft, ip: e.target.value })} />
        <input className="input mono" placeholder="username" value={draft.user} onChange={(e) => setDraft({ ...draft, user: e.target.value })} />
        <select className="input" value={draft.source} onChange={(e) => setDraft({ ...draft, source: e.target.value })}>
          <option value="">all sources</option>
          <option value="auth">auth</option>
          <option value="web">web</option>
          <option value="generic">csv/json</option>
        </select>
        <select className="input" value={draft.outcome} onChange={(e) => setDraft({ ...draft, outcome: e.target.value })}>
          <option value="">any outcome</option>
          <option value="failure">failures</option>
          <option value="success">successes</option>
        </select>
        <input className="input" placeholder="search raw log text…" value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />
        <div className="flex gap-2">
          <button className="btn-primary" type="submit">
            <Search className="h-4 w-4" /> Filter
          </button>
          <button className="btn-ghost" type="button" onClick={() => apply({})}>
            Clear
          </button>
        </div>
      </form>

      <ErrorBox error={error} />
      <div className="panel">
        {!result ? (
          <Spinner />
        ) : result.events.length === 0 ? (
          <Empty>No events match these filters.</Empty>
        ) : (
          <>
            <EventsTable events={result.events} onFilter={(f) => apply({ ...filters, ...f })} />
            <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xs text-muted">
              <span>
                {fmtNum(page * PAGE + 1)}–{fmtNum(page * PAGE + result.events.length)} of {fmtNum(result.total)} events
              </span>
              <div className="flex gap-2">
                <button className="btn-ghost px-3 py-1" disabled={page === 0} onClick={() => setParams({ ...Object.fromEntries(params), page: page - 1 })}>
                  Prev
                </button>
                <button
                  className="btn-ghost px-3 py-1"
                  disabled={(page + 1) * PAGE >= result.total}
                  onClick={() => setParams({ ...Object.fromEntries(params), page: page + 1 })}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
