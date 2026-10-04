// nginx / apache "combined" (and "common") access log format:
// 1.2.3.4 - alice [04/Oct/2026:03:12:45 +0000] "GET /x HTTP/1.1" 200 512 "-" "UA"

const LINE = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)(?:\s+[^"]*)?"\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?/;
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const LOGIN_PATH = /\/(login|signin|sign-in|auth|session|wp-login\.php)\b/i;

export function looksLikeWebLog(line) {
  return LINE.test(line);
}

function parseTime(s) {
  // 04/Oct/2026:03:12:45 +0000
  const m = s.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-])(\d{2})(\d{2})$/);
  if (!m) return new Date(NaN);
  const utc = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]);
  const offset = (m[7] === '-' ? -1 : 1) * (Number(m[8]) * 60 + Number(m[9]));
  return new Date(utc - offset * 60_000);
}

export function parseWebLog(text, { file = 'access.log' } = {}) {
  const events = [];
  let skipped = 0;

  text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    const m = line.match(LINE);
    const ts = m && parseTime(m[3]);
    if (!m || Number.isNaN(ts.getTime())) {
      skipped++;
      return;
    }

    const [, ip, user, , method, rawPath, statusStr, bytesStr, , ua] = m;
    const status = Number(statusStr);
    let path = rawPath;
    try {
      path = decodeURIComponent(rawPath);
    } catch {
      // keep raw path if it isn't valid URI encoding (attack payloads often aren't)
    }

    const isLogin = method === 'POST' && LOGIN_PATH.test(path);
    events.push({
      ts,
      source: 'web',
      file,
      lineNo: i + 1,
      ip,
      user: user === '-' ? null : user,
      action: isLogin ? 'login' : 'http',
      outcome: isLogin ? (status < 400 ? 'success' : 'failure') : status < 400 ? 'success' : 'failure',
      method,
      path,
      status,
      bytes: bytesStr === '-' ? 0 : Number(bytesStr),
      detail: ua && ua !== '-' ? ua : null,
      raw: line,
    });
  });

  return { events, skipped };
}
