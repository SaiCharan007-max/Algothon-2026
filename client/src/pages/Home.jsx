import { useEffect, useRef, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { UploadCloud, FileText, X, Play, Trash2, ShieldAlert, Loader2, Download } from 'lucide-react'
import { api } from '../api'
import { ErrorBox, SeverityBadge } from '../components/ui'
import { fmtNum, fmtTime, SEVERITY_ORDER } from '../lib/format'

const FORMAT_OPTIONS = [
  { value: '', label: 'Auto-detect' },
  { value: 'auth', label: 'Linux auth.log' },
  { value: 'web', label: 'nginx / apache access log' },
  { value: 'csv', label: 'CSV export' },
  { value: 'json', label: 'JSON / JSON lines' },
]

const RAW = 'https://raw.githubusercontent.com/SaiCharan007-max/Algothon-2026/main/samples'

export default function Home() {
  const navigate = useNavigate()
  const inputRef = useRef(null)
  const [files, setFiles] = useState([]) // [{file, format}]
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(null) // 'upload' | 'sample'
  const [error, setError] = useState(null)
  const [uploads, setUploads] = useState(null)

  const load = () => api.listUploads().then(setUploads).catch(setError)
  useEffect(() => {
    load()
  }, [])

  const addFiles = (list) => {
    const incoming = [...list].map((file) => ({ file, format: '' }))
    setFiles((prev) => [...prev, ...incoming].slice(0, 10))
    setError(null)
  }

  const analyze = async () => {
    setBusy('upload')
    setError(null)
    try {
      const res = await api.upload(
        files.map((f) => f.file),
        files.map((f) => f.format),
      )
      navigate(`/analysis/${res.id}`)
    } catch (e) {
      setError(e)
      setBusy(null)
    }
  }

  const runSample = async () => {
    setBusy('sample')
    setError(null)
    try {
      const res = await api.runSample()
      navigate(`/analysis/${res.id}`)
    } catch (e) {
      setError(e)
      setBusy(null)
    }
  }

  const remove = async (id) => {
    if (!confirm('Delete this analysis and all its stored events?')) return
    try {
      await api.deleteUpload(id)
      load()
    } catch (e) {
      setError(e)
    }
  }

  return (
    <div className="space-y-10">
      <section className="grid gap-8 lg:grid-cols-[1.1fr_1fr] lg:items-center">
        <div>
          <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-rose-500/30 bg-rose-500/10 px-3 py-1 text-xs text-rose-200">
            <ShieldAlert className="h-3.5 w-3.5" /> Log analysis · attack correlation · incident timelines
          </div>
          <h1 className="text-4xl font-semibold leading-tight tracking-tight text-white md:text-5xl">
            Find the intruder hiding in thousands of log lines.
          </h1>
          <p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted">
            Drop in your SSH <span className="mono text-slate-300">auth.log</span>, web server access logs or a CSV/JSON export. LogHound flags suspicious IPs and users,
            links related events across files, and rebuilds the likely attack sequence as a timeline, with the raw log lines as evidence.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <button className="btn-ghost" onClick={runSample} disabled={!!busy}>
              {busy === 'sample' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Run the sample attack scenario
            </button>
            <a className="btn-ghost" href={`${RAW}/auth.log`} target="_blank" rel="noreferrer">
              <Download className="h-4 w-4" /> sample auth.log
            </a>
            <a className="btn-ghost" href={`${RAW}/access.log`} target="_blank" rel="noreferrer">
              <Download className="h-4 w-4" /> sample access.log
            </a>
          </div>
        </div>

        <div className="panel p-5">
          <div
            onDragOver={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault()
              setDragging(false)
              addFiles(e.dataTransfer.files)
            }}
            onClick={() => inputRef.current?.click()}
            className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-10 text-center transition ${
              dragging ? 'border-rose-400 bg-rose-500/10' : 'border-line hover:border-slate-500'
            }`}
          >
            <UploadCloud className="h-9 w-9 text-slate-400" />
            <div className="mt-3 font-medium text-slate-200">Drop log files here or click to browse</div>
            <div className="mt-1 text-xs text-muted">Up to 10 files, 25 MB each. Upload several to correlate across them.</div>
            <input
              ref={inputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => {
                addFiles(e.target.files)
                e.target.value = ''
              }}
            />
          </div>

          {files.length > 0 && (
            <ul className="mt-4 space-y-2">
              {files.map((f, i) => (
                <li key={i} className="flex items-center gap-3 rounded-lg bg-panel-2 px-3 py-2">
                  <FileText className="h-4 w-4 shrink-0 text-slate-400" />
                  <span className="min-w-0 flex-1 truncate text-sm">{f.file.name}</span>
                  <span className="text-xs text-muted">{(f.file.size / 1024).toFixed(0)} KB</span>
                  <select
                    className="input py-1 text-xs"
                    value={f.format}
                    onChange={(e) => setFiles((prev) => prev.map((p, j) => (j === i ? { ...p, format: e.target.value } : p)))}
                  >
                    {FORMAT_OPTIONS.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                  <button className="text-slate-500 hover:text-white" onClick={() => setFiles((prev) => prev.filter((_, j) => j !== i))} title="Remove">
                    <X className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}

          <button className="btn-primary mt-4 w-full" disabled={!files.length || !!busy} onClick={analyze}>
            {busy === 'upload' ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
            {busy === 'upload' ? 'Analyzing…' : `Analyze ${files.length || ''} file${files.length === 1 ? '' : 's'}`}
          </button>
          <div className="mt-3">
            <ErrorBox error={error} />
          </div>
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-muted">Previous analyses</h2>
        <div className="panel overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-muted">
              <tr className="border-b border-line">
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Events</th>
                <th className="px-4 py-3 font-medium">Incidents</th>
                <th className="px-4 py-3 font-medium">Log time range (UTC)</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {uploads === null && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-muted">
                    Loading…
                  </td>
                </tr>
              )}
              {uploads?.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-muted">
                    Nothing analyzed yet. Upload logs or run the sample scenario.
                  </td>
                </tr>
              )}
              {uploads?.map((u) => (
                <tr key={u.id} className="border-b border-line/60 last:border-0 hover:bg-panel-2/60">
                  <td className="px-4 py-3">
                    <Link to={`/analysis/${u.id}`} className="font-medium text-slate-100 hover:text-rose-300">
                      {u.name}
                    </Link>
                    <div className="text-xs text-muted">analyzed {new Date(u.created_at).toLocaleString()}</div>
                  </td>
                  <td className="px-4 py-3 mono">{fmtNum(u.event_count)}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {SEVERITY_ORDER.filter((s) => u.by_severity?.[s]).map((s) => (
                        <SeverityBadge key={s} severity={s}>
                          {u.by_severity[s]} {s}
                        </SeverityBadge>
                      ))}
                      {!u.incidents && <span className="text-xs text-muted">none</span>}
                      {u.incidents > 0 && <span className="ml-1 text-xs text-muted">{u.incidents} total</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted">
                    {fmtTime(u.first_event, { seconds: false })} → {fmtTime(u.last_event, { seconds: false })}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button className="text-slate-500 hover:text-rose-400" onClick={() => remove(u.id)} title="Delete">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
