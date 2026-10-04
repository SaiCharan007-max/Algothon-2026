import { describe, it, expect } from 'vitest';
import { parseAuthLog } from '../src/parsers/authlog.js';
import { parseWebLog } from '../src/parsers/weblog.js';
import { parseCsv, parseJson, splitCsvLine } from '../src/parsers/structured.js';
import { detectFormat, parseFiles } from '../src/parsers/index.js';

describe('auth.log parser', () => {
  const log = [
    'Oct  3 02:10:01 web01 sshd[811]: Failed password for invalid user admin from 203.0.113.45 port 50122 ssh2',
    'Oct  3 02:10:03 web01 sshd[811]: Failed password for root from 203.0.113.45 port 50124 ssh2',
    'Oct  3 02:31:40 web01 sshd[901]: Accepted password for deploy from 203.0.113.45 port 50311 ssh2',
    'Oct  3 02:33:12 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow',
    'Oct  3 02:34:00 web01 sudo:    guest : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/guest ; USER=root ; COMMAND=/bin/bash',
    '2026-10-03T02:40:00+00:00 web01 sshd[1000]: Accepted publickey for alice from 10.0.0.12 port 2222 ssh2',
    'Oct  3 02:35:00 web01 CRON[123]: pam_unix(cron:session): session opened for user root',
    'this is not a log line',
  ].join('\n');

  const { events, skipped } = parseAuthLog(log, { year: 2026 });

  it('parses failed and accepted logins', () => {
    expect(events[0]).toMatchObject({ action: 'login', outcome: 'failure', user: 'admin', ip: '203.0.113.45' });
    expect(events[0].detail).toMatch(/invalid user/);
    expect(events[1]).toMatchObject({ user: 'root', outcome: 'failure' });
    expect(events[2]).toMatchObject({ action: 'login', outcome: 'success', user: 'deploy' });
    expect(events[2].ts.toISOString()).toBe('2026-10-03T02:31:40.000Z');
  });

  it('parses sudo commands and sudo failures', () => {
    expect(events[3]).toMatchObject({ action: 'sudo', outcome: 'success', user: 'deploy' });
    expect(events[3].detail).toContain('/etc/shadow');
    expect(events[4]).toMatchObject({ action: 'sudo', outcome: 'failure', user: 'guest' });
  });

  it('handles ISO timestamps', () => {
    expect(events[5]).toMatchObject({ user: 'alice', outcome: 'success', ip: '10.0.0.12' });
    expect(events[5].ts.toISOString()).toBe('2026-10-03T02:40:00.000Z');
  });

  it('skips lines it does not understand instead of crashing', () => {
    expect(events).toHaveLength(6);
    expect(skipped).toBe(2);
  });
});

describe('web access log parser', () => {
  const log = [
    '203.0.113.45 - - [03/Oct/2026:01:50:02 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.0"',
    '10.0.0.5 - alice [03/Oct/2026:07:15:00 +0530] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0"',
    '203.0.113.45 - - [03/Oct/2026:01:55:00 +0000] "GET /products?id=1%27%20OR%201=1-- HTTP/1.1" 500 0 "-" "sqlmap"',
    '1.1.1.1 - - [bad date] "GET / HTTP/1.1" 200 1',
  ].join('\n');
  const { events, skipped } = parseWebLog(log);

  it('parses combined format', () => {
    expect(events[0]).toMatchObject({ ip: '203.0.113.45', method: 'GET', path: '/.env', status: 404, action: 'http' });
  });

  it('treats POST /login as a login and applies the tz offset', () => {
    expect(events[1]).toMatchObject({ action: 'login', outcome: 'success', user: 'alice' });
    expect(events[1].ts.toISOString()).toBe('2026-10-03T01:45:00.000Z');
  });

  it('url-decodes paths so payloads are visible', () => {
    expect(events[2].path).toContain("' OR 1=1");
  });

  it('skips malformed lines', () => {
    expect(skipped).toBe(1);
  });
});

describe('structured parsers', () => {
  it('splits quoted csv fields', () => {
    expect(splitCsvLine('a,"b, c","say ""hi"""')).toEqual(['a', 'b, c', 'say "hi"']);
  });

  it('maps common column aliases from csv', () => {
    const csv = 'Timestamp,Source_IP,UserName,Event_Type,Result\n2026-10-03T02:00:00Z,1.2.3.4,bob,UserLogon,FAILED\n';
    const { events } = parseCsv(csv);
    expect(events[0]).toMatchObject({ ip: '1.2.3.4', user: 'bob', action: 'login', outcome: 'failure' });
  });

  it('parses json arrays and json lines', () => {
    const arr = parseJson('[{"time": 1790000000, "ip": "9.9.9.9", "action": "login", "success": true}]');
    expect(arr.events[0]).toMatchObject({ ip: '9.9.9.9', action: 'login', outcome: 'success' });
    const lines = parseJson('{"ts":"2026-10-03T00:00:00Z","user":"x","event":"sudo"}\nnot json\n');
    expect(lines.events).toHaveLength(1);
    expect(lines.skipped).toBe(1);
  });
});

describe('format detection + merge', () => {
  it('detects formats from content', () => {
    expect(detectFormat('x.txt', 'Oct  3 02:10:01 web01 sshd[811]: Failed password for root from 1.2.3.4 port 1 ssh2')).toBe('auth');
    expect(detectFormat('x.txt', '1.2.3.4 - - [03/Oct/2026:01:50:02 +0000] "GET / HTTP/1.1" 200 1 "-" "-"')).toBe('web');
    expect(detectFormat('x.csv', 'a,b')).toBe('csv');
  });

  it('merges files into one time-ordered timeline with seq numbers', () => {
    const { events, files } = parseFiles(
      [
        { name: 'auth.log', text: 'Oct  3 02:10:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2' },
        { name: 'access.log', text: '1.2.3.4 - - [03/Oct/2026:02:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"' },
      ],
      { year: 2026 },
    );
    expect(events.map((e) => e.source)).toEqual(['web', 'auth']);
    expect(events.map((e) => e.seq)).toEqual([0, 1]);
    expect(files.map((f) => f.format)).toEqual(['auth', 'web']);
  });
});
