import { useEffect, useRef, useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { UploadCloud, FileText, X, Play, Trash2, Loader2, ShieldAlert, ShieldCheck, ChevronRight, Download } from 'lucide-react'
import { api } from '../api'
import { ErrorBox } from '../components/ui'

const SAMPLES = [
  {
    name: 'attack.log',
    title: 'Server that got hacked',
    text: '3 days of normal SSH activity with a break-in hidden inside.',
    icon: ShieldAlert,
    tone: 'text-sev-critical',
  },
  {
    name: 'normal.log',
    title: 'Healthy server',
    text: '3 days of normal SSH activity only. Nothing bad should show up.',
    icon: ShieldCheck,
    tone: 'text-emerald-400',
  },
]

export default function Home() {
  const navigate = useNavigate()
  const inputRef = useRef(null)
  const [files, setFiles] = useState([])
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(null) // 'upload' | sample file name
  const [error, setError] = useState(null)
  const [uploads, setUploads] = useState(null)

  const load = () => api.listUploads().then(setUploads).catch(setError)
  useEffect(() => {
    load()
  }, [])

  const addFiles = (list) => {
    setFiles((prev) => [...prev, ...list].slice(0, 10))
    setError(null)
  }

  const run = async (kind) => {
    setBusy(kind)
    setError(null)
    try {
      // format is auto-detected on the server
      const res = kind === 'upload' ? await api.upload(files, files.map(() => '')) : await api.runSample(kind)
      navigate(`/analysis/${res.id}`)
    } catch (e) {
      setError(e)
      setBusy(null)
    }
  }

  const remove = async (id) => {
    if (!confirm('Delete this check?')) return
    try {
      await api.deleteUpload(id)
      load()
    } catch (e) {
      setError(e)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-10">
      <section className="pt-4 text-center">
        <h1 className="text-3xl font-semibold tracking-tight text-white md:text-4xl">Did someone break into your server?</h1>
        <p className="mt-3 text-[15px] text-muted">Upload your server's log files and we'll tell you, in plain English, what happened and what to do.</p>
        <div className="mt-6 flex flex-wrap justify-center gap-x-6 gap-y-2 text-sm text-slate-400">
          <span>
            <b className="text-slate-200">1.</b> Upload logs
          </span>
          <span>
            <b className="text-slate-200">2.</b> We check them
          </span>
          <span>
            <b className="text-slate-200">3.</b> See what happened
          </span>
        </div>
      </section>

      <section className="panel p-5">
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
          className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed px-6 py-12 text-center transition ${
            dragging ? 'border-rose-400 bg-rose-500/10' : 'border-line hover:border-slate-500'
          }`}
        >
          <UploadCloud className="h-10 w-10 text-slate-400" />
          <div className="mt-3 text-lg font-medium text-slate-100">Drop your log files here</div>
          <div className="mt-1 text-sm text-muted">or click to choose files</div>
          <div className="mt-4 text-xs text-slate-500">Works with SSH logs (auth.log), website logs (access.log), CSV and JSON</div>
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
              <li key={i} className="flex items-center gap-3 rounded-lg bg-panel-2 px-3 py-2 text-sm">
                <FileText className="h-4 w-4 shrink-0 text-slate-400" />
                <span className="min-w-0 flex-1 truncate">{f.name}</span>
                <span className="text-xs text-muted">{Math.max(1, Math.round(f.size / 1024))} KB</span>
                <button className="text-slate-500 hover:text-white" onClick={() => setFiles((prev) => prev.filter((_, j) => j !== i))} title="Remove">
                  <X className="h-4 w-4" />
                </button>
              </li>
            ))}
          </ul>
        )}

        {files.length > 0 && (
          <button className="btn-primary mt-4 w-full py-3 text-base" disabled={!!busy} onClick={() => run('upload')}>
            {busy === 'upload' ? <Loader2 className="h-5 w-5 animate-spin" /> : <ShieldAlert className="h-5 w-5" />}
            {busy === 'upload' ? 'Checking…' : 'Check for attacks'}
          </button>
        )}

        <div className="mt-4">
          <ErrorBox error={error} />
        </div>

      </section>

      <section>
        <h2 className="text-sm font-medium text-slate-300">No logs of your own? Try one of these</h2>
        <p className="mt-1 text-xs text-muted">Download a file to look at it and upload it above yourself, or let us check it straight away.</p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          {SAMPLES.map((smp) => (
            <div key={smp.name} className="panel flex flex-col p-4">
              <div className="flex items-center gap-2">
                <smp.icon className={`h-5 w-5 ${smp.tone}`} />
                <span className="font-medium text-white">{smp.title}</span>
              </div>
              <div className="mono mt-1 text-slate-400">{smp.name}</div>
              <p className="mt-2 flex-1 text-sm text-muted">{smp.text}</p>
              <div className="mt-4 flex gap-2">
                <a className="btn-ghost flex-1" href={api.sampleUrl(smp.name)} download={smp.name}>
                  <Download className="h-4 w-4" /> Download
                </a>
                <button className="btn-primary flex-1" onClick={() => run(smp.name)} disabled={!!busy}>
                  {busy === smp.name ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                  Check it now
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {uploads?.length > 0 && (
        <section>
          <h2 className="mb-3 text-sm font-medium text-muted">Your previous checks</h2>
          <ul className="panel divide-y divide-line">
            {uploads.map((u) => {
              const bad = (u.by_severity?.critical || 0) + (u.by_severity?.high || 0)
              const sus = u.by_severity?.medium || 0
              return (
                <li key={u.id} className="flex items-center gap-3 px-4 py-3 hover:bg-panel-2/60">
                  {bad ? <ShieldAlert className="h-5 w-5 shrink-0 text-sev-critical" /> : <ShieldCheck className="h-5 w-5 shrink-0 text-emerald-400" />}
                  <Link to={`/analysis/${u.id}`} className="min-w-0 flex-1">
                    <div className="truncate font-medium text-slate-100">{u.name}</div>
                    <div className="text-xs text-muted">
                      {bad ? `${bad} attack${bad > 1 ? 's' : ''} found` : sus ? `${sus} thing${sus > 1 ? 's' : ''} to check` : 'Nothing serious found'} ·{' '}
                      {new Date(u.created_at).toLocaleString()}
                    </div>
                  </Link>
                  <button className="text-slate-600 hover:text-rose-400" onClick={() => remove(u.id)} title="Delete">
                    <Trash2 className="h-4 w-4" />
                  </button>
                  <ChevronRight className="h-4 w-4 text-slate-600" />
                </li>
              )
            })}
          </ul>
        </section>
      )}
    </div>
  )
}
