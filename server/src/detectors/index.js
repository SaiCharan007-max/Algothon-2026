import { mergeConfig } from './config.js';
import { bruteForce, passwordSpray, compromisedLogin, unusualLogin } from './auth.js';
import { suspiciousCommands } from './commands.js';
import { recon, webAttack, exfiltration } from './web.js';

export const RULES = [
  { id: 'brute_force', run: bruteForce, cfg: 'bruteForce' },
  { id: 'password_spray', run: passwordSpray, cfg: 'spray' },
  { id: 'compromised_login', run: compromisedLogin, cfg: 'compromise' },
  { id: 'unusual_login', run: unusualLogin, cfg: 'unusualLogin' },
  { id: 'suspicious_command', run: suspiciousCommands, cfg: 'commands' },
  { id: 'recon_scan', run: recon, cfg: 'recon' },
  { id: 'web_attack', run: webAttack, cfg: 'webAttack' },
  { id: 'data_exfiltration', run: exfiltration, cfg: 'exfil' },
];

// events must already be sorted by time (parseFiles does that)
export function runDetectors(events, overrides) {
  const cfg = mergeConfig(overrides);
  const alerts = RULES.flatMap((r) => r.run(events, cfg[r.cfg]));
  alerts.sort((a, b) => a.firstSeen - b.firstSeen);
  alerts.forEach((a, i) => (a.key = i));
  return alerts;
}
