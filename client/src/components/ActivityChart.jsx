import { ResponsiveContainer, ComposedChart, Area, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Legend } from 'recharts'
import { fmtTime } from '../lib/format'

function TipContent({ active, payload, label }) {
  if (!active || !payload?.length) return null
  const row = payload[0].payload
  return (
    <div className="rounded-lg border border-line bg-panel-2 px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 font-medium text-slate-200">{fmtTime(label, { seconds: false })} UTC</div>
      <div className="text-slate-400">events: <span className="text-slate-200">{row.events}</span></div>
      <div className="text-slate-400">failures: <span className="text-amber-300">{row.failures}</span></div>
      <div className="text-slate-400">alerts started: <span className="text-rose-300">{row.alerts}</span></div>
    </div>
  )
}

export default function ActivityChart({ histogram }) {
  const data = histogram?.buckets || []
  if (!data.length) return null
  const spanDays = (new Date(data[data.length - 1].t) - new Date(data[0].t)) / 86400000

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer>
        <ComposedChart data={data} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
          <defs>
            <linearGradient id="evFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="t"
            tick={{ fill: '#64748b', fontSize: 11 }}
            tickFormatter={(t) => (spanDays > 1.5 ? fmtTime(t, { seconds: false }) : fmtTime(t, { date: false, seconds: false }))}
            minTickGap={40}
            stroke="#1e293b"
          />
          <YAxis yAxisId="ev" tick={{ fill: '#64748b', fontSize: 11 }} stroke="#1e293b" allowDecimals={false} />
          <YAxis yAxisId="al" orientation="right" hide allowDecimals={false} />
          <Tooltip content={<TipContent />} cursor={{ stroke: '#334155' }} />
          <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} iconType="circle" iconSize={8} />
          <Area yAxisId="ev" type="monotone" dataKey="events" name="Events" stroke="#38bdf8" strokeWidth={1.5} fill="url(#evFill)" />
          <Area yAxisId="ev" type="monotone" dataKey="failures" name="Failures (4xx / failed login)" stroke="#eab308" strokeWidth={1.5} fill="transparent" />
          <Bar yAxisId="al" dataKey="alerts" name="Alerts" fill="#f43f5e" barSize={6} radius={[2, 2, 0, 0]} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  )
}
