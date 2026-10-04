// Scores the detector on files where we know the right answer (our sample
// files, which the generator labels line by line). Shown on the results page
// as "How accurate was this?".
import { generate } from '../scripts/generate-logs.js';

const SERIOUS = new Set(['medium', 'high', 'critical']);
const norm = (text) => text.replace(/\r\n/g, '\n').trimEnd();

let known = null;
function knownSamples() {
  if (known) return known;
  const full = generate();
  const normal = generate({ seed: 7, attack: false, distractors: false });
  known = [
    { text: full.auth, labels: full.labels.auth },
    { text: full.access, labels: full.labels.access },
    { text: normal.auth, labels: normal.labels.auth },
  ].map((k) => ({ ...k, text: norm(k.text) }));
  return known;
}

// { [uploadedFileName]: labels } for every uploaded file that is one of our samples
export function matchSamples(files) {
  const out = {};
  for (const f of files) {
    const hit = knownSamples().find((k) => k.text === norm(f.text));
    if (hit) out[f.name] = hit.labels;
  }
  return Object.keys(out).length ? out : null;
}

export function evaluate(events, alerts, incidents, truth) {
  const sevOfIncident = new Map(incidents.map((i) => [i.ref, i.severity]));
  // worst finding level each event was flagged under
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  const flaggedAs = new Map();
  for (const a of alerts) {
    const sev = sevOfIncident.get(a.incidentRef) || a.severity;
    for (const seq of a.evidence) {
      if (!flaggedAs.has(seq) || rank[sev] > rank[flaggedAs.get(seq)]) flaggedAs.set(seq, sev);
    }
  }

  const res = {
    attack: { total: 0, caught: 0, missed: [] },
    attempt: { total: 0, caught: 0 },
    normal: { total: 0, falseAlarms: 0, minorNotes: 0 },
    odd: { total: 0, flagged: 0 },
  };

  for (const e of events) {
    const labels = truth[e.file];
    if (!labels) continue;
    const kind = labels.attack.includes(e.lineNo) ? 'attack' : labels.attempt.includes(e.lineNo) ? 'attempt' : labels.odd.includes(e.lineNo) ? 'odd' : 'normal';
    const sev = flaggedAs.get(e.seq);
    res[kind].total++;
    if (kind === 'attack') {
      if (sev) res.attack.caught++;
      else if (res.attack.missed.length < 5) res.attack.missed.push({ file: e.file, line: e.lineNo, raw: e.raw });
    } else if (kind === 'attempt') {
      if (sev) res.attempt.caught++;
    } else if (kind === 'odd') {
      if (sev) res.odd.flagged++;
    } else if (sev) {
      if (SERIOUS.has(sev)) res.normal.falseAlarms++;
      else res.normal.minorNotes++;
    }
  }
  res.files = Object.keys(truth);
  return res;
}
