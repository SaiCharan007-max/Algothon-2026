// All detection thresholds in one place so they're easy to tune / explain.
const MIN = 60_000;

export const DEFAULT_CONFIG = {
  bruteForce: { windowMs: 5 * MIN, minFailures: 10, sessionGapMs: 10 * MIN },
  spray: { sessionGapMs: 15 * MIN, minUsers: 5 },
  compromise: { lookbackMs: 30 * MIN, minPriorFailures: 5 },
  unusualLogin: { minHistory: 3, hourTolerance: 2 },
  commands: { sessionGapMs: 30 * MIN },
  recon: { sessionGapMs: 10 * MIN, minErrors: 20, minProbePaths: 3 },
  webAttack: { sessionGapMs: 30 * MIN },
  exfil: { sessionGapMs: 15 * MIN, minRequestBytes: 5 * 1024 * 1024, medianMultiplier: 50, criticalTotalBytes: 100 * 1024 * 1024 },
};

export function mergeConfig(overrides = {}) {
  const out = {};
  for (const [k, v] of Object.entries(DEFAULT_CONFIG)) out[k] = { ...v, ...(overrides[k] || {}) };
  return out;
}
