// CSV / JSON / JSON-lines exports (SIEM dumps, cloud audit logs, etc).
// Column names vary a lot between tools so we match on a list of aliases.

const ALIASES = {
  ts: ['timestamp', 'time', 'ts', '@timestamp', 'datetime', 'date', 'event_time', 'eventtime'],
  ip: ['ip', 'src_ip', 'source_ip', 'sourceip', 'client_ip', 'clientip', 'remote_addr', 'ip_address', 'srcaddr'],
  user: ['user', 'username', 'user_name', 'account', 'login', 'actor', 'userid', 'user_id'],
  action: ['action', 'event', 'event_type', 'eventtype', 'type', 'activity', 'eventname'],
  outcome: ['outcome', 'status', 'result', 'success'],
  method: ['method', 'http_method', 'verb'],
  path: ['path', 'url', 'uri', 'request', 'resource', 'endpoint'],
  status: ['status_code', 'http_status', 'response_code', 'code'],
  bytes: ['bytes', 'bytes_sent', 'size', 'response_size', 'body_bytes_sent', 'bytes_out'],
  detail: ['detail', 'details', 'message', 'msg', 'command', 'description'],
};

function pick(row, keys) {
  for (const k of keys) {
    if (row[k] !== undefined && row[k] !== null && row[k] !== '') return row[k];
  }
  return null;
}

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase().trim()] = v;
  return out;
}

function normalizeAction(value, path) {
  const v = String(value ?? '').toLowerCase();
  if (/login|logon|auth|signin|sign_in|ssh/.test(v)) return 'login';
  if (/sudo|privilege|elevat|su\b|admin/.test(v)) return 'sudo';
  if (/logout|logoff|session/.test(v)) return 'session';
  if (/http|request|get|post|download|access/.test(v) || path) return 'http';
  return 'other';
}

function normalizeOutcome(value, status) {
  if (value === true) return 'success';
  if (value === false) return 'failure';
  const v = String(value ?? '').toLowerCase();
  if (/fail|denied|invalid|error|reject|false|blocked/.test(v)) return 'failure';
  if (/succ|ok|accept|allow|true|pass/.test(v)) return 'success';
  if (/^\d{3}$/.test(v)) return Number(v) < 400 ? 'success' : 'failure';
  if (status) return status < 400 ? 'success' : 'failure';
  return null;
}

function toDate(value) {
  if (value === null) return new Date(NaN);
  if (typeof value === 'number' || /^\d{10,13}$/.test(String(value))) {
    const n = Number(value);
    return new Date(n < 1e12 ? n * 1000 : n); // seconds vs millis
  }
  return new Date(value);
}

function rowToEvent(row, { file, lineNo, raw }) {
  const r = lowerKeys(row);
  const ts = toDate(pick(r, ALIASES.ts));
  if (Number.isNaN(ts.getTime())) return null;

  const path = pick(r, ALIASES.path);
  let status = pick(r, ALIASES.status);
  const outcomeRaw = pick(r, ALIASES.outcome);
  // "status" is sometimes the http code, sometimes "success"/"failure"
  if (status === null && /^\d{3}$/.test(String(outcomeRaw ?? ''))) status = outcomeRaw;
  status = status === null ? null : Number(status) || null;
  const bytes = pick(r, ALIASES.bytes);

  return {
    ts,
    source: 'generic',
    file,
    lineNo,
    ip: pick(r, ALIASES.ip) ? String(pick(r, ALIASES.ip)) : null,
    user: pick(r, ALIASES.user) ? String(pick(r, ALIASES.user)) : null,
    action: normalizeAction(pick(r, ALIASES.action), path),
    outcome: normalizeOutcome(outcomeRaw, status),
    method: pick(r, ALIASES.method) ? String(pick(r, ALIASES.method)).toUpperCase() : null,
    path: path ? String(path) : null,
    status,
    bytes: bytes === null ? null : Number(bytes) || 0,
    detail: pick(r, ALIASES.detail) ? String(pick(r, ALIASES.detail)) : null,
    raw,
  };
}

// small CSV splitter that handles quoted fields with commas / escaped quotes
export function splitCsvLine(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (c === '"') quoted = false;
      else cur += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') {
      out.push(cur);
      cur = '';
    } else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

export function parseCsv(text, { file = 'events.csv' } = {}) {
  const lines = text.split(/\r?\n/);
  const header = splitCsvLine(lines[0] || '');
  const events = [];
  let skipped = 0;

  for (let i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    const cells = splitCsvLine(lines[i]);
    const row = Object.fromEntries(header.map((h, j) => [h, cells[j]]));
    const ev = rowToEvent(row, { file, lineNo: i + 1, raw: lines[i] });
    if (ev) events.push(ev);
    else skipped++;
  }
  return { events, skipped };
}

export function parseJson(text, { file = 'events.json' } = {}) {
  const events = [];
  let skipped = 0;
  const trimmed = text.trim();

  if (trimmed.startsWith('[')) {
    let rows;
    try {
      rows = JSON.parse(trimmed);
    } catch {
      return { events, skipped: 1 };
    }
    rows.forEach((row, i) => {
      const ev = row && typeof row === 'object' ? rowToEvent(row, { file, lineNo: i + 1, raw: JSON.stringify(row) }) : null;
      if (ev) events.push(ev);
      else skipped++;
    });
    return { events, skipped };
  }

  // JSON lines
  text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    try {
      const ev = rowToEvent(JSON.parse(line), { file, lineNo: i + 1, raw: line });
      if (ev) events.push(ev);
      else skipped++;
    } catch {
      skipped++;
    }
  });
  return { events, skipped };
}
