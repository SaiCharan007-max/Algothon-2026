import { groupBy, sessions, makeAlert, median, formatBytes, minutesBetween, uniq } from '../lib/util.js';

const httpEvents = (events) => events.filter((e) => e.path && (e.action === 'http' || e.action === 'login'));

// paths that only scanners / attackers ask for
const PROBE_PATHS = [
  /\/\.env\b/, /\/\.git\//, /\/\.svn/, /\/\.htaccess/, /\/\.aws/, /\/\.ssh/, /wp-(admin|login|config)/, /phpmyadmin/i, /\/xmlrpc\.php/,
  /\/server-status/, /\/actuator/, /\/cgi-bin\//, /\/config\.(php|json|yml)/, /\/backup/, /\/\.DS_Store/, /\/(adminer|shell|cmd)\.php/,
];

const SCANNER_UA = /(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wfuzz|ffuf|nuclei|acunetix|hydra)/i;

const PAYLOADS = [
  { kind: 'SQL injection', re: /('|%27)\s*(or|and)\s+['\d]|union\s+(all\s+)?select|sleep\(\d+\)|benchmark\(|information_schema|;\s*drop\s+table|--\s*$/i },
  { kind: 'Path traversal', re: /\.\.\/|\.\.\\|%2e%2e|\/etc\/passwd|win\.ini/i },
  { kind: 'XSS', re: /<script|javascript:|onerror\s*=|onload\s*=|<img\s+src/i },
  { kind: 'Command injection', re: /;\s*(cat|ls|id|whoami|wget|curl|nc|bash)\b|\|\s*(cat|id|whoami)\b|`[^`]+`|\$\([^)]*\)/i },
  { kind: 'Log4Shell / JNDI', re: /\$\{jndi:/i },
];

// lots of 4xx / probing for well-known sensitive files
export function recon(events, cfg) {
  const alerts = [];
  for (const [ip, evs] of groupBy(httpEvents(events), (e) => e.ip)) {
    for (const s of sessions(evs, cfg.sessionGapMs)) {
      const errors = s.filter((e) => e.status >= 400 && e.status < 500);
      const probes = s.filter((e) => PROBE_PATHS.some((p) => p.test(e.path)));
      const scannerUa = s.some((e) => SCANNER_UA.test(e.detail || ''));
      if (errors.length < cfg.minErrors && probes.length < cfg.minProbePaths && !scannerUa) continue;

      const evidence = uniq([...probes, ...errors]).sort((a, b) => a.seq - b.seq);
      const paths = uniq(probes.map((e) => e.path));
      alerts.push(
        makeAlert({
          rule: 'recon_scan',
          stage: 'Reconnaissance',
          severity: 'medium',
          entityType: 'ip',
          entity: ip,
          title: `Web scanning from ${ip}`,
          description: `${s.length} requests in ${minutesBetween(s[0].ts, s[s.length - 1].ts) || '<1'} min, ${errors.length} returned 4xx${paths.length ? `; probed ${paths.slice(0, 5).join(', ')}` : ''}${scannerUa ? '; scanner user-agent seen' : ''}.`,
          events: evidence.length ? evidence : s,
          meta: { requests: s.length, errors: errors.length, probes: paths },
        }),
      );
    }
  }
  return alerts;
}

// attack payloads in the URL
export function webAttack(events, cfg) {
  const alerts = [];
  const hits = [];
  for (const e of httpEvents(events)) {
    const kinds = PAYLOADS.filter((p) => p.re.test(e.path)).map((p) => p.kind);
    if (kinds.length) hits.push({ e, kinds });
  }

  for (const [ip, list] of groupBy(hits, (h) => h.e.ip)) {
    const byEvent = new Map(list.map((h) => [h.e, h.kinds]));
    for (const s of sessions(list.map((h) => h.e), cfg.sessionGapMs)) {
      const kinds = uniq(s.flatMap((e) => byEvent.get(e)));
      const succeeded = s.filter((e) => e.status && e.status < 400);
      alerts.push(
        makeAlert({
          rule: 'web_attack',
          stage: 'Exploitation',
          severity: succeeded.length ? 'high' : 'medium',
          entityType: 'ip',
          entity: ip,
          title: `${kinds.join(' / ')} attempts from ${ip}`,
          description: `${s.length} request(s) with ${kinds.join(', ')} payloads; ${succeeded.length} got a non-error response (possible success). Example: ${s[0].method || ''} ${s[0].path.slice(0, 120)}`,
          events: s,
          meta: { kinds, succeeded: succeeded.length },
        }),
      );
    }
  }
  return alerts;
}

// responses way bigger than normal = data being pulled out
export function exfiltration(events, cfg) {
  const alerts = [];
  const web = httpEvents(events).filter((e) => e.bytes > 0);
  const typical = median(web.map((e) => e.bytes));
  const threshold = Math.max(cfg.minRequestBytes, typical * cfg.medianMultiplier);
  const big = web.filter((e) => e.bytes >= threshold && e.status < 400);

  for (const [ip, evs] of groupBy(big, (e) => e.ip)) {
    for (const s of sessions(evs, cfg.sessionGapMs)) {
      const total = s.reduce((sum, e) => sum + e.bytes, 0);
      const paths = uniq(s.map((e) => e.path.split('?')[0]));
      alerts.push(
        makeAlert({
          rule: 'data_exfiltration',
          stage: 'Exfiltration',
          severity: total >= cfg.criticalTotalBytes ? 'critical' : 'high',
          entityType: 'ip',
          entity: ip,
          title: `Large data transfer to ${ip}`,
          description: `${formatBytes(total)} downloaded in ${s.length} response(s) (typical response is ${formatBytes(Math.round(typical))}) from ${paths.slice(0, 4).join(', ')}.`,
          events: s,
          meta: { totalBytes: total, typicalBytes: typical, user: uniq(s.map((e) => e.user))[0] || null },
        }),
      );
    }
  }
  return alerts;
}
