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

// "what's the risk" text shown in the popup next to a suspicious log line
const STAGE_RISK = {
  'Privilege Escalation': 'Reading the password file or giving an account admin rights lets an attacker take full control of the server.',
  Persistence: 'A new account, SSH key or scheduled job lets the attacker get back in even after you change the password.',
  'Defense Evasion': 'Deleting logs or turning off security tools is done to hide what happened, so you might not see everything.',
  Exfiltration: 'Data is being bundled up or sent off the server. This is how data gets stolen.',
}

const RULE_RISK = {
  brute_force: 'Someone is trying password after password. If any account has a weak password, they will eventually get in.',
  password_spray: 'They are trying lots of usernames to find accounts that exist and have a weak password.',
  compromised_login: 'This login worked right after a long run of wrong guesses. The attacker most likely guessed the password and is now inside.',
  unusual_login: "This account logged in from somewhere it has never used before. Fine if it's really them (e.g. working from home), bad if the password was stolen.",
  sudo_denied: 'An account without admin rights tried to run admin commands. Usually a mistake, but it can be an attacker testing what they can do.',
  recon_scan: 'Someone is probing the website for secret files (.env, .git, admin pages). Finding one could leak passwords or keys.',
  web_attack: 'These requests contain hacking code such as SQL injection. If the website is vulnerable, the attacker can read or change your database.',
  data_exfiltration: 'Far more data than normal was downloaded. This can mean your database is being copied out.',
}

export function riskText(alert) {
  return (alert.rule === 'suspicious_command' && STAGE_RISK[alert.stage]) || RULE_RISK[alert.rule] || alert.description
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
