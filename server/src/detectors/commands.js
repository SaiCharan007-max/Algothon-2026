import { groupBy, sessions, makeAlert } from '../lib/util.js';

// patterns for commands run through sudo/su, grouped by what the attacker is after
export const COMMAND_RULES = [
  {
    stage: 'Privilege Escalation',
    severity: 'high',
    title: 'read password files or gave themselves admin rights',
    label: 'reading credential stores / changing sudo rights',
    patterns: [/\/etc\/shadow/, /\/etc\/sudoers/, /visudo/, /usermod\s+.*-a?G\s*(sudo|wheel|admin|root)/, /chmod\s+[ugo]*\+s|chmod\s+[0-7]?[4-7][0-7]{3}\s/, /\bsu\s+-?\s*root\b/, /\/bin\/(ba)?sh\s*$/],
  },
  {
    stage: 'Persistence',
    severity: 'high',
    title: 'created a backdoor (new account, SSH key or scheduled job)',
    label: 'creating accounts / keys / scheduled tasks',
    patterns: [/\buseradd\b|\badduser\b/, /authorized_keys/, /\bcrontab\b|\/etc\/cron/, /systemctl\s+enable/, /\bpasswd\s+\w+/],
  },
  {
    stage: 'Defense Evasion',
    severity: 'high',
    title: 'tried to delete logs or turn off security tools',
    label: 'tampering with logs / security tools',
    patterns: [/history\s+-c/, /(rm|shred|truncate).*\/var\/log/, />\s*\/var\/log/, /systemctl\s+(stop|disable)\s+(auditd|rsyslog|syslog|fail2ban|ufw|firewalld)/, /iptables\s+-F/, /setenforce\s+0/],
  },
  {
    stage: 'Exfiltration',
    severity: 'high',
    title: 'packed up data and sent it off the server',
    label: 'packing / sending data off the box',
    patterns: [/\b(tar|zip)\b.*\/(var\/www|home|etc|opt|srv|backup)/, /\bscp\b.*@/, /\brsync\b.*@/, /curl\s+.*(-T|--upload-file|-F|--data-binary)/, /\bnc\b.*\s\d+\s*</, /mysqldump|pg_dump/],
  },
];

function classify(cmd) {
  const hits = [];
  for (const rule of COMMAND_RULES) {
    if (rule.patterns.some((p) => p.test(cmd))) hits.push(rule);
  }
  return hits;
}

// sudo / su activity: sensitive commands + people trying sudo without rights
export function suspiciousCommands(events, cfg) {
  const alerts = [];
  const sudo = events.filter((e) => e.action === 'sudo' && e.user);

  for (const [user, evs] of groupBy(sudo, (e) => e.user)) {
    for (const s of sessions(evs, cfg.sessionGapMs)) {
      // bucket matched commands per stage inside this session
      const byStage = new Map();
      for (const e of s) {
        if (e.outcome === 'failure') continue;
        for (const rule of classify(e.detail || '')) {
          if (!byStage.has(rule.stage)) byStage.set(rule.stage, { rule, events: [] });
          byStage.get(rule.stage).events.push(e);
        }
      }
      for (const { rule, events: hit } of byStage.values()) {
        const cmds = hit.map((e) => (e.detail || '').replace(/^as \S+: /, ''));
        alerts.push(
          makeAlert({
            rule: 'suspicious_command',
            stage: rule.stage,
            severity: rule.severity,
            entityType: 'user',
            entity: user,
            title: `${user} ${rule.title}`,
            description: `${user} ran ${hit.length} command(s) ${rule.label}: ${cmds.slice(0, 3).join(' | ')}${cmds.length > 3 ? ' …' : ''}`,
            events: hit,
            meta: { commands: cmds },
          }),
        );
      }

      const denied = s.filter((e) => e.outcome === 'failure');
      if (denied.length) {
        alerts.push(
          makeAlert({
            rule: 'sudo_denied',
            stage: 'Privilege Escalation',
            severity: denied.length >= 3 ? 'medium' : 'low',
            entityType: 'user',
            entity: user,
            title: `${user} tried to use admin rights and was blocked`,
            description: `${denied.length} sudo/su attempt(s) by ${user} were denied.`,
            events: denied,
          }),
        );
      }
    }
  }
  return alerts;
}
