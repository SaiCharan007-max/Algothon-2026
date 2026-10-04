// Linux auth.log / secure (sshd, sudo, su). Supports classic syslog
// timestamps ("Oct  4 03:12:45") and RFC3339 ones from newer rsyslog.

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

const CLASSIC = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+([\w.\-/]+)(?:\[\d+\])?:\s*(.*)$/;
const ISO = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(\S+)\s+([\w.\-/]+)(?:\[\d+\])?:\s*(.*)$/;

export function looksLikeAuthLog(line) {
  return (CLASSIC.test(line) || ISO.test(line)) && /(sshd|sudo|su|login|systemd-logind)/.test(line);
}

function parseHeader(line, year) {
  let m = line.match(ISO);
  if (m) return { ts: new Date(m[1]), host: m[2], program: m[3], msg: m[4] };
  m = line.match(CLASSIC);
  if (m) {
    const ts = new Date(Date.UTC(year, MONTHS[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])));
    return { ts, host: m[6], program: m[7], msg: m[8] };
  }
  return null;
}

function parseMessage(program, msg) {
  const prog = program.split('/').pop();

  if (prog === 'sshd') {
    let m = msg.match(/^Failed (password|publickey) for (invalid user )?(\S+) from (\S+)/);
    if (m) {
      return { action: 'login', outcome: 'failure', user: m[3], ip: m[4], detail: `${m[2] ? 'invalid user, ' : ''}${m[1]}` };
    }
    m = msg.match(/^Accepted (\S+) for (\S+) from (\S+)/);
    if (m) return { action: 'login', outcome: 'success', user: m[2], ip: m[3], detail: m[1] };
    m = msg.match(/^Invalid user (\S*) from (\S+)/);
    if (m) return { action: 'login', outcome: 'failure', user: m[1] || null, ip: m[2], detail: 'invalid user' };
    m = msg.match(/authentication failure;.*rhost=(\S+)(?:\s+user=(\S+))?/);
    if (m) return { action: 'login', outcome: 'failure', user: m[2] || null, ip: m[1], detail: 'pam auth failure' };
    m = msg.match(/^Disconnected from (?:(?:invalid |authenticating )?user (\S+) )?(\S+)/);
    if (m) return { action: 'session', outcome: 'success', user: m[1] || null, ip: m[2], detail: 'disconnect' };
    return null;
  }

  if (prog === 'sudo') {
    // "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    let m = msg.match(/^\s*(\S+)\s*:\s*(.*?)\s*;?\s*TTY=.*?USER=(\S+)\s*;\s*COMMAND=(.*)$/);
    if (m) {
      const failed = /not in sudoers|incorrect password|authentication failure/i.test(m[2]);
      return {
        action: 'sudo',
        outcome: failed ? 'failure' : 'success',
        user: m[1],
        detail: `${failed ? m[2] + ' | ' : ''}as ${m[3]}: ${m[4]}`,
      };
    }
    m = msg.match(/authentication failure;.*user=(\S+)/);
    if (m) return { action: 'sudo', outcome: 'failure', user: m[1], detail: 'sudo auth failure' };
    return null;
  }

  if (prog === 'su') {
    const m = msg.match(/(Successful|FAILED) su for (\S+) by (\S+)/i);
    if (m) {
      return {
        action: 'sudo',
        outcome: /succ/i.test(m[1]) ? 'success' : 'failure',
        user: m[3],
        detail: `su to ${m[2]}`,
      };
    }
  }
  return null;
}

export function parseAuthLog(text, { file = 'auth.log', year = new Date().getUTCFullYear() } = {}) {
  const events = [];
  let skipped = 0;
  const lines = text.split(/\r?\n/);

  lines.forEach((line, i) => {
    if (!line.trim()) return;
    const header = parseHeader(line, year);
    const body = header && parseMessage(header.program, header.msg);
    if (!header || !body || Number.isNaN(header.ts.getTime())) {
      skipped++;
      return;
    }
    events.push({
      ts: header.ts,
      source: 'auth',
      file,
      lineNo: i + 1,
      ip: body.ip ?? null,
      user: body.user ?? null,
      action: body.action,
      outcome: body.outcome ?? null,
      method: null,
      path: null,
      status: null,
      bytes: null,
      detail: body.detail ?? null,
      raw: line,
    });
  });

  return { events, skipped };
}
