import { groupBy, sessions, maxInWindow, makeAlert, minutesBetween, uniq } from '../lib/util.js';

const logins = (events) => events.filter((e) => e.action === 'login');

// many failed logins from one IP in a short window
export function bruteForce(events, cfg) {
  const alerts = [];
  const failures = logins(events).filter((e) => e.outcome === 'failure' && e.ip);

  for (const [ip, evs] of groupBy(failures, (e) => e.ip)) {
    for (const s of sessions(evs, cfg.sessionGapMs)) {
      const peak = maxInWindow(s, cfg.windowMs);
      if (peak < cfg.minFailures) continue;
      const users = uniq(s.map((e) => e.user));
      const mins = minutesBetween(s[0].ts, s[s.length - 1].ts);
      alerts.push(
        makeAlert({
          rule: 'brute_force',
          stage: 'Credential Access',
          severity: 'high',
          entityType: 'ip',
          entity: ip,
          title: `${ip} tried to guess passwords`,
          description: `${s.length} failed logins in ${mins || '<1'} min (peak ${peak} within ${cfg.windowMs / 60_000} min) against ${users.length} account(s): ${users.slice(0, 6).join(', ')}${users.length > 6 ? '…' : ''}.`,
          events: s,
          meta: { failures: s.length, peak, users },
        }),
      );
    }
  }
  return alerts;
}

// one IP trying lots of different usernames = password spraying / user enumeration
export function passwordSpray(events, cfg) {
  const alerts = [];
  const failures = logins(events).filter((e) => e.outcome === 'failure' && e.ip && e.user);

  for (const [ip, evs] of groupBy(failures, (e) => e.ip)) {
    for (const s of sessions(evs, cfg.sessionGapMs)) {
      const users = uniq(s.map((e) => e.user));
      if (users.length < cfg.minUsers) continue;
      alerts.push(
        makeAlert({
          rule: 'password_spray',
          stage: 'Credential Access',
          severity: 'high',
          entityType: 'ip',
          entity: ip,
          title: `${ip} tried lots of different usernames`,
          description: `${ip} tried ${users.length} different usernames (${users.slice(0, 8).join(', ')}${users.length > 8 ? '…' : ''}) in ${minutesBetween(s[0].ts, s[s.length - 1].ts) || '<1'} min.`,
          events: s,
          meta: { users },
        }),
      );
    }
  }
  return alerts;
}

// a successful login right after a pile of failures - the brute force worked
export function compromisedLogin(events, cfg) {
  const alerts = [];
  const all = logins(events);
  const failsByIp = groupBy(all.filter((e) => e.outcome === 'failure' && e.ip), (e) => e.ip);
  const failsByUser = groupBy(all.filter((e) => e.outcome === 'failure' && e.user), (e) => e.user);
  const flagged = new Set();

  for (const ok of all.filter((e) => e.outcome === 'success')) {
    const since = ok.ts - cfg.lookbackMs;
    // prefer failures from the same log source (ssh fails shouldn't explain a web login)
    const recent = (list) => {
      const inWindow = (list || []).filter((f) => f.ts >= since && f.ts <= ok.ts);
      const sameSource = inWindow.filter((f) => f.source === ok.source);
      return sameSource.length >= cfg.minPriorFailures ? sameSource : inWindow;
    };
    const ipFails = recent(failsByIp.get(ok.ip));
    const userFails = recent(failsByUser.get(ok.user));
    const fromIp = ipFails.length >= cfg.minPriorFailures;
    const onUser = userFails.length >= cfg.minPriorFailures;
    if (!fromIp && !onUser) continue;

    const key = `${ok.ip}|${ok.user}`;
    if (flagged.has(key)) continue; // one alert per ip+user pair is enough
    flagged.add(key);

    const prior = fromIp ? ipFails : userFails;
    // everything the same ip + account did in the hour after getting in
    const after = events.filter((e) => e.ip === ok.ip && e.user === ok.user && e.ts > ok.ts && e.ts - ok.ts <= cfg.followMs);
    const alert = makeAlert({
      rule: 'compromised_login',
      stage: 'Initial Access',
      severity: 'critical',
      entityType: 'user',
      entity: ok.user,
      title: `Attacker got into the "${ok.user}" account`,
      description: (fromIp
        ? `${ok.ip} logged in successfully as "${ok.user}" after ${ipFails.length} failed attempts in the previous ${cfg.lookbackMs / 60_000} min.`
        : `"${ok.user}" logged in from ${ok.ip} after ${userFails.length} failed attempts on that account in the previous ${cfg.lookbackMs / 60_000} min.`) +
        (after.length ? ` After getting in, the same session did ${after.length} more thing(s).` : ''),
      events: [...prior.slice(-10), ok, ...after],
      meta: { ip: ok.ip, priorFailures: prior.length, source: ok.source },
    });
    // the moment of compromise is the successful login, not the first failure
    alert.firstSeen = ok.ts;
    alerts.push(alert);
  }
  return alerts;
}

// successful login from an IP the user has never used before. An odd hour on
// its own is too noisy to alert on, but it raises the severity of a new-IP login.
export function unusualLogin(events, cfg) {
  const alerts = [];
  const successes = logins(events).filter((e) => e.outcome === 'success' && e.user);

  for (const [user, evs] of groupBy(successes, (e) => e.user)) {
    const seenIps = new Set();
    const seenHours = [];
    for (const e of evs) {
      const hour = e.ts.getUTCHours();
      if (seenHours.length >= cfg.minHistory && e.ip && !seenIps.has(e.ip)) {
        const reasons = [`first login ever from ${e.ip}`];
        const dist = (h) => Math.min(Math.abs(h - hour), 24 - Math.abs(h - hour));
        if (!seenHours.some((h) => dist(h) <= cfg.hourTolerance)) {
          reasons.push(`at ${String(hour).padStart(2, '0')}:xx UTC, outside this user's usual hours`);
        }
        alerts.push(
          makeAlert({
            rule: 'unusual_login',
            stage: 'Initial Access',
            severity: reasons.length > 1 ? 'medium' : 'low',
            entityType: 'user',
            entity: user,
            title: `${user} logged in from a new location`,
            description: `${user}: ${reasons.join(' ')} (baseline: ${seenHours.length} earlier logins from ${seenIps.size} IP(s)).`,
            events: [e],
            meta: { ip: e.ip, reasons },
          }),
        );
      }
      if (e.ip) seenIps.add(e.ip);
      seenHours.push(hour);
    }
  }
  return alerts;
}
