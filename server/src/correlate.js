import { SEVERITY_WEIGHT, STAGES, uniq, minutesBetween } from './lib/util.js';

// tiny union-find over entity keys like "ip:1.2.3.4" / "user:alice"
class UnionFind {
  constructor() {
    this.parent = new Map();
  }
  find(x) {
    if (!this.parent.has(x)) this.parent.set(x, x);
    let root = x;
    while (this.parent.get(root) !== root) root = this.parent.get(root);
    this.parent.set(x, root);
    return root;
  }
  union(a, b) {
    this.parent.set(this.find(a), this.find(b));
  }
}

const entityKey = (type, value) => `${type}:${value}`;

// plain-english actions, written for someone who isn't a security person
const RECOMMENDATIONS = {
  Reconnaissance: (ips) => `Block ${ips.join(', ')} on your firewall.`,
  Exploitation: () => 'Ask a developer to check the attacked pages for SQL injection / input bugs.',
  'Credential Access': () => 'Turn on account lockout after a few wrong passwords, and use 2-factor login.',
  'Initial Access': (_ips, users) => `Change the password of ${users.join(', ') || 'the affected accounts'} and log them out everywhere.`,
  'Privilege Escalation': () => 'Change the admin (root) password and check who is allowed to use sudo.',
  Persistence: () => 'Delete any new user accounts, SSH keys or scheduled jobs the attacker created.',
  'Defense Evasion': () => 'Some logs may have been wiped - get copies from your backups.',
  Exfiltration: () => 'Find out what data was taken and change any passwords or keys that were in it.',
};

// what each stage looks like in one short phrase, used to write the summary
const STAGE_VERBS = {
  Reconnaissance: () => 'scanned the website for weak spots',
  Exploitation: () => 'tried to hack the website',
  'Credential Access': () => 'tried to guess passwords',
  'Initial Access': (users) => (users.length ? `logged in as ${users.join(' and ')}` : 'got into an account'),
  'Privilege Escalation': () => 'tried to get admin access',
  Persistence: () => 'set up a backdoor to come back later',
  'Defense Evasion': () => 'tried to hide their tracks',
  Exfiltration: () => 'copied data out',
};

const joinList = (items) => (items.length <= 1 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`);

function severityFromScore(score) {
  if (score >= 80) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

const fmtTime = (d) => d.toISOString().slice(11, 16) + ' UTC';

function fmtDuration(mins) {
  if (mins < 1) return 'under a minute';
  if (mins < 120) return `${mins} minutes`;
  if (mins < 48 * 60) return `${Math.round(mins / 60)} hours`;
  return `${Math.round(mins / 1440)} days`;
}

// score = strongest alert per rule + bonus for every extra kill-chain stage
function scoreIncident(alerts, stages) {
  const perRule = new Map();
  for (const a of alerts) perRule.set(a.rule, Math.max(perRule.get(a.rule) || 0, SEVERITY_WEIGHT[a.severity]));
  const base = Math.max(...perRule.values());
  const others = [...perRule.values()].reduce((s, v) => s + v, 0) - base;
  const chainBonus = Math.max(0, stages.length - 1) * 10;
  return Math.min(100, Math.round(base + others * 0.25 + chainBonus));
}

function buildStory(alerts, ips, users, stages) {
  const steps = alerts.map((a) => ({
    time: a.firstSeen,
    stage: a.stage,
    severity: a.severity,
    text: a.description,
    alertKey: a.key,
  }));

  const first = alerts[0].firstSeen;
  const last = alerts.reduce((m, a) => (a.lastSeen > m ? a.lastSeen : m), first);
  // only call it an attack once there's real attack behaviour, low stuff may be benign
  const confident = stages.length > 1 || alerts.some((a) => a.severity === 'high' || a.severity === 'critical');
  const who = ips.length ? ips.join(', ') : users.join(', ');
  const mins = minutesBetween(first, last);
  const when = mins < 1 ? `at ${fmtTime(first)}` : `over ${fmtDuration(mins)}, starting ${fmtTime(first)}`;
  const verbs = stages.map((s) => STAGE_VERBS[s](users));

  let summary;
  if (stages.length > 1) {
    summary = `Someone at ${who} ${joinList(verbs)} - ${when}.`;
  } else if (confident) {
    summary = `${who} ${verbs[0]} ${when}. There's no sign they got any further.`;
  } else {
    summary = `${alerts[0].title} ${when}. Probably harmless, but worth a quick look.`;
  }

  return {
    summary,
    steps,
    recommendations: stages.map((s) => RECOMMENDATIONS[s]?.(ips, users)).filter(Boolean),
  };
}

function titleFor(alerts, stages, ips, users) {
  const actor = ips[0] || users[0];
  if (stages.length >= 3 && stages.includes('Initial Access')) return `Break-in from ${actor}`;
  if (stages.length >= 3) return `Repeated attack attempts from ${actor}`;
  const top = [...alerts].sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity])[0];
  return top.title;
}

// Group alerts into incidents. Two entities are linked when:
//  - an alert is about both (e.g. compromised_login has user + ip)
//  - a flagged IP successfully logged in as a user
export function correlate(alerts, events) {
  const uf = new UnionFind();
  const flagged = new Set();

  for (const a of alerts) {
    const k = entityKey(a.entityType, a.entity);
    flagged.add(k);
    uf.find(k);
    const ip = a.meta?.ip;
    if (ip && a.entityType === 'user') {
      uf.union(k, entityKey('ip', ip));
      flagged.add(entityKey('ip', ip));
    }
    const user = a.meta?.user;
    if (user && a.entityType === 'ip') uf.union(k, entityKey('user', user));
  }

  // successful logins from a flagged ip pull that user into the same incident
  for (const e of events) {
    if (e.action !== 'login' || e.outcome !== 'success' || !e.ip || !e.user) continue;
    const ipKey = entityKey('ip', e.ip);
    if (flagged.has(ipKey)) uf.union(ipKey, entityKey('user', e.user));
  }
  // authenticated web requests from a flagged ip as well
  for (const e of events) {
    if (e.source !== 'web' || !e.ip || !e.user) continue;
    const ipKey = entityKey('ip', e.ip);
    if (flagged.has(ipKey)) uf.union(ipKey, entityKey('user', e.user));
  }

  const groups = new Map();
  for (const a of alerts) {
    const root = uf.find(entityKey(a.entityType, a.entity));
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(a);
  }

  const incidents = [...groups.values()].map((group) => {
    group.sort((a, b) => a.firstSeen - b.firstSeen);
    // ips ordered by how many alerts point at them, so the main actor comes first
    const ipHits = new Map();
    for (const a of group) {
      for (const ip of uniq([a.entityType === 'ip' ? a.entity : null, a.meta?.ip])) ipHits.set(ip, (ipHits.get(ip) || 0) + 1);
    }
    const ips = [...ipHits.keys()].sort((a, b) => ipHits.get(b) - ipHits.get(a));
    const users = uniq(group.flatMap((a) => [a.entityType === 'user' ? a.entity : null, a.meta?.user]));
    // users the flagged ips logged in as
    const root = uf.find(entityKey(group[0].entityType, group[0].entity));
    for (const k of uf.parent.keys()) {
      if (k.startsWith('user:') && uf.find(k) === root) users.push(k.slice(5));
    }
    const allUsers = uniq(users);
    const stages = STAGES.filter((s) => group.some((a) => a.stage === s));
    const score = scoreIncident(group, stages);

    return {
      title: titleFor(group, stages, ips, allUsers),
      severity: severityFromScore(score),
      score,
      ips,
      users: allUsers,
      stages,
      story: buildStory(group, ips, allUsers, stages),
      firstSeen: group[0].firstSeen,
      lastSeen: group.reduce((m, a) => (a.lastSeen > m ? a.lastSeen : m), group[0].lastSeen),
      alertKeys: group.map((a) => a.key),
    };
  });

  incidents.sort((a, b) => b.score - a.score || a.firstSeen - b.firstSeen);
  incidents.forEach((inc, i) => {
    inc.ref = `INC-${String(i + 1).padStart(3, '0')}`;
    for (const k of inc.alertKeys) alerts[k].incidentRef = inc.ref;
  });
  return incidents;
}
