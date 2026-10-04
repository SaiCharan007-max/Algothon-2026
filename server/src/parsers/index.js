import { parseAuthLog, looksLikeAuthLog } from './authlog.js';
import { parseWebLog, looksLikeWebLog } from './weblog.js';
import { parseCsv, parseJson } from './structured.js';

export const FORMATS = ['auth', 'web', 'csv', 'json'];

// guess the format from the file name first, then from the first few lines
export function detectFormat(name, text) {
  const lower = (name || '').toLowerCase();
  if (lower.endsWith('.csv')) return 'csv';
  if (lower.endsWith('.json') || lower.endsWith('.jsonl') || lower.endsWith('.ndjson')) return 'json';

  const sample = text.split(/\r?\n/).filter((l) => l.trim()).slice(0, 20);
  if (!sample.length) return null;
  if (/^[[{]/.test(sample[0].trim())) return 'json';

  const score = (fn) => sample.filter(fn).length;
  const web = score(looksLikeWebLog);
  const auth = score(looksLikeAuthLog);
  if (web === 0 && auth === 0) {
    return sample[0].includes(',') ? 'csv' : null;
  }
  return web >= auth ? 'web' : 'auth';
}

export function parseFile(name, text, format = detectFormat(name, text), opts = {}) {
  const ctx = { file: name, ...opts };
  switch (format) {
    case 'auth':
      return { format, ...parseAuthLog(text, ctx) };
    case 'web':
      return { format, ...parseWebLog(text, ctx) };
    case 'csv':
      return { format, ...parseCsv(text, ctx) };
    case 'json':
      return { format, ...parseJson(text, ctx) };
    default:
      return { format: null, events: [], skipped: text.split(/\r?\n/).filter((l) => l.trim()).length };
  }
}

// parse several files into one sorted timeline, each event gets a seq number
export function parseFiles(files, opts = {}) {
  const all = [];
  const fileInfo = [];

  for (const f of files) {
    const res = parseFile(f.name, f.text, f.format || undefined, opts);
    fileInfo.push({
      name: f.name,
      format: res.format,
      parsed: res.events.length,
      skipped: res.skipped,
    });
    all.push(...res.events);
  }

  all.sort((a, b) => a.ts - b.ts || a.lineNo - b.lineNo);
  all.forEach((e, i) => (e.seq = i));
  return { events: all, files: fileInfo };
}
