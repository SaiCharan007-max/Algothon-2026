import { runDetectors } from './detectors/index.js';
import { correlate } from './correlate.js';
import { SEVERITY_WEIGHT, groupBy } from './lib/util.js';

// per-entity risk: sum of alert weights, capped at 100
function rankEntities(alerts, events) {
  const entities = new Map();
  const ensure = (type, value) => {
    const k = `${type}:${value}`;
    if (!entities.has(k)) {
      entities.set(k, { type, value, risk: 0, alerts: 0, rules: new Set(), incidents: new Set(), events: 0, firstSeen: null, lastSeen: null });
    }
    return entities.get(k);
  };

  for (const a of alerts) {
    const ent = ensure(a.entityType, a.entity);
    ent.risk += SEVERITY_WEIGHT[a.severity];
    ent.alerts++;
    ent.rules.add(a.rule);
    if (a.incidentRef) ent.incidents.add(a.incidentRef);
  }

  const byIp = groupBy(events, (e) => e.ip);
  const byUser = groupBy(events, (e) => e.user);
  for (const ent of entities.values()) {
    const evs = (ent.type === 'ip' ? byIp : byUser).get(ent.value) || [];
    ent.events = evs.length;
    ent.firstSeen = evs[0]?.ts ?? null;
    ent.lastSeen = evs[evs.length - 1]?.ts ?? null;
  }

  return [...entities.values()]
    .map((e) => ({ ...e, risk: Math.min(100, e.risk), rules: [...e.rules], incidents: [...e.incidents] }))
    .sort((a, b) => b.risk - a.risk || b.alerts - a.alerts);
}

// event volume per bucket for the activity chart (~60 buckets)
function histogram(events, alerts) {
  if (!events.length) return [];
  const start = events[0].ts.getTime();
  const end = events[events.length - 1].ts.getTime();
  const steps = [60_000, 5 * 60_000, 15 * 60_000, 3_600_000, 6 * 3_600_000, 86_400_000];
  const bucketMs = steps.find((s) => (end - start) / s <= 80) || 86_400_000;
  const first = Math.floor(start / bucketMs) * bucketMs;
  const n = Math.floor((end - first) / bucketMs) + 1;

  const buckets = Array.from({ length: n }, (_, i) => ({ t: new Date(first + i * bucketMs).toISOString(), events: 0, failures: 0, alerts: 0 }));
  for (const e of events) {
    const b = buckets[Math.floor((e.ts.getTime() - first) / bucketMs)];
    b.events++;
    if (e.outcome === 'failure') b.failures++;
  }
  for (const a of alerts) {
    const idx = Math.floor((a.firstSeen.getTime() - first) / bucketMs);
    if (buckets[idx]) buckets[idx].alerts++;
  }
  return { bucketMs, buckets };
}

export function analyze(events, config) {
  const alerts = runDetectors(events, config);
  const incidents = correlate(alerts, events);
  const entities = rankEntities(alerts, events);

  const count = (fn) => events.filter(fn).length;
  const stats = {
    events: events.length,
    sources: Object.fromEntries([...groupBy(events, (e) => e.source)].map(([k, v]) => [k, v.length])),
    uniqueIps: new Set(events.map((e) => e.ip).filter(Boolean)).size,
    uniqueUsers: new Set(events.map((e) => e.user).filter(Boolean)).size,
    failedLogins: count((e) => e.action === 'login' && e.outcome === 'failure'),
    successfulLogins: count((e) => e.action === 'login' && e.outcome === 'success'),
    alerts: alerts.length,
    incidents: incidents.length,
    bySeverity: Object.fromEntries(['critical', 'high', 'medium', 'low'].map((s) => [s, incidents.filter((i) => i.severity === s).length])),
    firstEvent: events[0]?.ts ?? null,
    lastEvent: events[events.length - 1]?.ts ?? null,
  };

  return { alerts, incidents, entities, stats, histogram: histogram(events, alerts) };
}
