export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

export const STAGES = [
  'Reconnaissance',
  'Exploitation',
  'Credential Access',
  'Initial Access',
  'Privilege Escalation',
  'Persistence',
  'Defense Evasion',
  'Exfiltration',
]

// friendly name for each attack stage (technical name is shown small next to it)
export const STAGE_LABELS = {
  Reconnaissance: 'Looked for weak spots',
  Exploitation: 'Tried to hack the website',
  'Credential Access': 'Guessed passwords',
  'Initial Access': 'Got into an account',
  'Privilege Escalation': 'Went after admin access',
  Persistence: 'Set up a backdoor',
  'Defense Evasion': 'Tried to hide tracks',
  Exfiltration: 'Took data',
}

export const SEVERITY_INFO = {
  critical: { label: 'Act now', hint: 'Someone very likely broke in.' },
  high: { label: 'Serious', hint: 'A real attack, but it may not have worked.' },
  medium: { label: 'Suspicious', hint: 'Worth checking soon.' },
  low: { label: 'Minor', hint: 'Probably harmless.' },
}

export const RULE_LABELS = {
  brute_force: 'Brute force',
  password_spray: 'Password spray',
  compromised_login: 'Compromised login',
  unusual_login: 'Unusual login',
  suspicious_command: 'Sensitive command',
  sudo_denied: 'Sudo denied',
  recon_scan: 'Web scanning',
  web_attack: 'Injection payload',
  data_exfiltration: 'Large data transfer',
}

const pad = (n) => String(n).padStart(2, '0')

// everything is shown in UTC so it lines up with the raw log lines
export function fmtTime(iso, { date = true, seconds = true } = {}) {
  if (!iso) return '—'
  const d = new Date(iso)
  const t = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${seconds ? ':' + pad(d.getUTCSeconds()) : ''}`
  if (!date) return t
  return `${d.toLocaleString('en-GB', { day: '2-digit', month: 'short', timeZone: 'UTC' })} ${t}`
}

export function fmtDuration(a, b) {
  const mins = Math.round((new Date(b) - new Date(a)) / 60000)
  if (mins < 1) return '< 1 min'
  if (mins < 120) return `${mins} min`
  if (mins < 2880) return `${Math.round(mins / 60)} h`
  return `${Math.round(mins / 1440)} days`
}

export function fmtBytes(n) {
  if (n == null) return '—'
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${n} B`
}

export const fmtNum = (n) => (n ?? 0).toLocaleString('en-US')
