import { useEffect, useState, useCallback } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { Activity, AlertOctagon, Crosshair, KeyRound, Users, ArrowLeft, ChevronRight, FileWarning, Search } from 'lucide-react'
import { api } from '../api'
import { SeverityBadge, ScoreBar, Chip, StageChain, Spinner, ErrorBox, StatCard, Empty, SEV_COLOR } from '../components/ui'
import ActivityChart from '../components/ActivityChart'
import EventsTable from '../components/EventsTable'
import { fmtTime, fmtDuration, fmtNum, RULE_LABELS } from '../lib/format'

const TABS = [
  { id: 'incidents', label: 'Incidents' },
  { id: 'entities', label: 'Suspicious IPs & users' },
  { id: 'alerts', label: 'All alerts' },
  { id: 'events', label: 'Event explorer' },
]

export default function Analysis() {
  const { id } = useParams()
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') || 'incidents'
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(() => {
    setError(null)
    api.getUpload(id).then(setData).catch(setError)
  }, [id])
  useEffect(load, [load])

  const setTab = (t, extra = {}) => setParams({ tab: t, ...extra })

  if (error) return <ErrorBox error={error} onRetry={load} />
  if (!data) return <Spinner label="Loading analysis…" />

  const { stats, histogram, entities } = data.summary
  const skipped = data.files.reduce((s, f) => s + f.skipped, 0)
  const flaggedIps = entities.filter((e) => e.type === 'ip').length

  return (
    <div className="space-y-6">
      <div>
        <Link to="/" className="mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-white">
          <ArrowLeft className="h-3.5 w-3.5" /> All analyses
        </Link>
        <h1 className="text-2xl font-semibold text-white">{data.name}</h1>
        <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
          <span>
            {fmtTime(stats.firstEvent)} → {fmtTime(stats.lastEvent)} UTC
          </span>
          {data.files.map((f) => (
            <span key={f.name} className="mono">
              {f.name} <span className="text-slate-500">({f.format}, {fmtNum(f.parsed)} events)</span>
            </span>
          ))}
        </div>
        {skipped > 0 && (
          <div className="mt-3 inline-flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-200">
            <FileWarning className="h-3.5 w-3.5" /> {fmtNum(skipped)} line(s) were not recognised and skipped. They can be found in the original file.
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard label="Events analyzed" value={fmtNum(stats.events)} sub={`${fmtNum(stats.uniqueIps)} IPs · ${fmtNum(stats.uniqueUsers)} users`} icon={Activity} />
        <StatCard
          label="Incidents"
          value={stats.incidents}
          sub={`${stats.bySeverity.critical} critical · ${stats.bySeverity.high} high`}
          icon={AlertOctagon}
          accent={stats.bySeverity.critical ? 'text-sev-critical' : 'text-slate-100'}
        />
        <StatCard label="Alerts" value={stats.alerts} sub="from 9 detection rules" icon={Crosshair} />
        <StatCard label="Flagged entities" value={entities.length} sub={`${flaggedIps} IPs · ${entities.length - flaggedIps} users`} icon={Users} />
        <StatCard label="Failed logins" value={fmtNum(stats.failedLogins)} sub={`${fmtNum(stats.successfulLogins)} successful`} icon={KeyRound} />
      </div>

      <div className="panel p-4">
        <div className="mb-2 text-sm font-medium text-slate-300">Activity over time</div>
        <ActivityChart histogram={histogram} />
      </div>

      <div>
        <div className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`whitespace-nowrap border-b-2 px-4 py-2 text-sm transition ${
                tab === t.id ? 'border-rose-400 text-white' : 'border-transparent text-muted hover:text-slate-200'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {tab === 'incidents' && <Incidents id={id} incidents={data.incidents} />}
        {tab === 'entities' && <Entities entities={entities} onPick={(f) => setTab('events', f)} />}
        {tab === 'alerts' && <Alerts id={id} alerts={data.alerts} />}
        {tab === 'events' && <Explorer id={id} params={params} setParams={setParams} />}
      </div>
    </div>
  )
}

function Incidents({ id, incidents }) {
  if (!incidents.length) return <Empty>No incidents. Nothing in these logs matched a detection rule.</Empty>
  return (
    <div className="space-y-3">
      {incidents.map((inc) => (
        <Link
          key={inc.id}
          to={`/analysis/${id}/incident/${inc.ref}`}
          className="panel group block p-4 transition hover:border-slate-600"
          style={{ borderLeft: `3px solid ${SEV_COLOR[inc.severity]}` }}
        >
          <div className="flex flex-wrap items-center gap-3">
            <span className="mono text-muted">{inc.ref}</span>
            <SeverityBadge severity={inc.severity} />
            <ScoreBar score={inc.score} severity={inc.severity} />
            <span className="ml-auto text-xs text-muted">
              {fmtTime(inc.first_seen)} · {fmtDuration(inc.first_seen, inc.last_seen)} · {inc.alert_count} alert{inc.alert_count === 1 ? '' : 's'}
            </span>
          </div>
          <div className="mt-2 flex items-center gap-2 text-lg font-medium text-white">
            {inc.title}
            <ChevronRight className="h-4 w-4 text-slate-500 transition group-hover:translate-x-0.5" />
          </div>
          <p className="mt-1 text-sm text-muted">{inc.story.summary}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {inc.ips.map((ip) => (
              <Chip key={ip} tone="ip">
                {ip}
              </Chip>
            ))}
            {inc.users.map((u) => (
              <Chip key={u} tone="user">
                {u}
              </Chip>
            ))}
          </div>
          <div className="mt-3">
            <StageChain stages={inc.stages} />
          </div>
        </Link>
      ))}
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
