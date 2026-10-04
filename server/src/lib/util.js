export const SEVERITY_WEIGHT = { low: 10, medium: 25, high: 50, critical: 80 };
export const SEVERITIES = ['low', 'medium', 'high', 'critical'];

// kill-chain order, used for sorting stages and building the story
export const STAGES = [
  'Reconnaissance',
  'Exploitation',
  'Credential Access',
  'Initial Access',
  'Privilege Escalation',
  'Persistence',
  'Defense Evasion',
  'Exfiltration',
];

export function groupBy(items, keyFn) {
  const map = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (key === null || key === undefined) continue;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(item);
  }
  return map;
}

// split time-sorted events into "sessions": a new session starts when
// the gap to the previous event is bigger than gapMs
export function sessions(events, gapMs) {
  const out = [];
  let cur = [];
  for (const e of events) {
    if (cur.length && e.ts - cur[cur.length - 1].ts > gapMs) {
      out.push(cur);
      cur = [];
    }
    cur.push(e);
  }
  if (cur.length) out.push(cur);
  return out;
}

// biggest number of events that fall inside any window of windowMs
export function maxInWindow(events, windowMs) {
  let best = 0;
  let start = 0;
  for (let end = 0; end < events.length; end++) {
    while (events[end].ts - events[start].ts > windowMs) start++;
    best = Math.max(best, end - start + 1);
  }
  return best;
}

export function median(nums) {
  if (!nums.length) return 0;
  const s = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

export const minutesBetween = (a, b) => Math.max(0, Math.round((b - a) / 60_000));

export function formatBytes(n) {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

export const uniq = (arr) => [...new Set(arr.filter((x) => x !== null && x !== undefined))];

// keep evidence lists readable - first N and last few events
export function sampleEvidence(events, max = 40) {
  if (events.length <= max) return events.map((e) => e.seq);
  const head = events.slice(0, max - 5);
  const tail = events.slice(-5);
  return [...head, ...tail].map((e) => e.seq);
}

export function makeAlert({ rule, stage, severity, entityType, entity, title, description, events, meta = {} }) {
  return {
    rule,
    stage,
    severity,
    entityType,
    entity,
    title,
    description,
    firstSeen: events[0].ts,
    lastSeen: events[events.length - 1].ts,
    evidence: sampleEvidence(events),
    eventCount: events.length,
    meta,
  };
}
