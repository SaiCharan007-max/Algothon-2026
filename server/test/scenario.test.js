// End-to-end: generate the sample logs, run the whole pipeline and check
// (1) the planted attack is found as one connected incident, and
// (2) normal users / services are NOT flagged above low severity.
import { describe, it, expect } from 'vitest';
import { generate, ATTACKER_IP, NOISE_IP } from '../scripts/generate-logs.js';
import { parseFiles } from '../src/parsers/index.js';
import { analyze } from '../src/analyze.js';
import { evaluate, matchSamples } from '../src/evaluate.js';

const run = (seed) => {
  const { auth, access } = generate({ seed });
  const { events } = parseFiles([{ name: 'auth.log', text: auth }, { name: 'access.log', text: access }], { year: 2026 });
  return { events, ...analyze(events) };
};

describe('planted attack scenario', () => {
  const { incidents, alerts, entities } = run(42);
  const top = incidents[0];

  it('ranks the real attack as the top, critical incident', () => {
    expect(top.severity).toBe('critical');
    expect(top.ips[0]).toBe(ATTACKER_IP);
    expect(top.users).toEqual(expect.arrayContaining(['deploy', 'mike']));
  });

  it('reconstructs the full attack chain in order', () => {
    expect(top.stages).toEqual([
      'Reconnaissance',
      'Exploitation',
      'Credential Access',
      'Initial Access',
      'Privilege Escalation',
      'Persistence',
      'Defense Evasion',
      'Exfiltration',
    ]);
    const times = top.story.steps.map((s) => +s.time);
    expect(times).toEqual([...times].sort((a, b) => a - b));
  });

  it('keeps the failed internet brute force as a separate, lower incident', () => {
    const noise = incidents.find((i) => i.ips.includes(NOISE_IP));
    expect(noise).toBeDefined();
    expect(noise.ref).not.toBe(top.ref);
    expect(['medium', 'high']).toContain(noise.severity);
  });

  it('does not flag normal employees, the CI server or routine admin work', () => {
    const normalUsers = ['alice', 'bob', 'dave', 'devops', 'priya', 'arjun', 'sneha', 'rahul'];
    for (const u of normalUsers) expect(alerts.filter((a) => a.entity === u)).toHaveLength(0);
    expect(entities.find((e) => e.value === '10.0.5.20')).toBeUndefined();
    // nothing other than the attack + the noisy scanner is above "low"
    const serious = incidents.filter((i) => i.severity !== 'low');
    expect(serious.map((i) => i.ips[0]).sort()).toEqual([NOISE_IP, ATTACKER_IP].sort());
  });

  it('every alert carries evidence pointing at real events', () => {
    for (const a of alerts) expect(a.evidence.length).toBeGreaterThan(0);
  });
});

describe('accuracy against the generator labels', () => {
  it.each([42, 1, 7, 1234])('seed %i: every attack line caught, no false alarms on normal lines', (seed) => {
    const { auth, access, labels } = generate({ seed });
    const { events } = parseFiles([{ name: 'auth.log', text: auth }, { name: 'access.log', text: access }], { year: 2026 });
    const { alerts, incidents } = analyze(events);
    const score = evaluate(events, alerts, incidents, { 'auth.log': labels.auth, 'access.log': labels.access });
    expect(score.attack.caught).toBe(score.attack.total);
    expect(score.attempt.caught).toBe(score.attempt.total);
    expect(score.normal.falseAlarms).toBe(0);
  });

  it('recognises an uploaded sample file even with windows line endings', () => {
    const { auth } = generate();
    expect(matchSamples([{ name: 'x.log', text: auth.replace(/\n/g, '\r\n') }])).not.toBeNull();
    expect(matchSamples([{ name: 'x.log', text: auth + 'extra line\n' }])).toBeNull();
  });
});

describe('clean logs (no attack, no distractors)', () => {
  it.each([7, 42, 1234])('seed %i produces zero alerts', (seed) => {
    const { auth, access } = generate({ seed, attack: false, distractors: false });
    const { events } = parseFiles([{ name: 'auth.log', text: auth }, { name: 'access.log', text: access }], { year: 2026 });
    const { alerts, incidents } = analyze(events);
    expect(alerts).toEqual([]);
    expect(incidents).toEqual([]);
  });
});

describe('robustness across random seeds', () => {
  it.each([1, 7, 1234, 9999])('seed %i still finds the attack without extra serious incidents', (seed) => {
    const { incidents } = run(seed);
    expect(incidents[0].ips[0]).toBe(ATTACKER_IP);
    expect(incidents[0].severity).toBe('critical');
    expect(incidents.filter((i) => i.severity === 'critical')).toHaveLength(1);
  });
});
