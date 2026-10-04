// MITRE ATT&CK technique for each detection, so findings use the same
// vocabulary security teams use. https://attack.mitre.org
export const T = {
  passwordGuessing: { id: 'T1110.001', name: 'Brute Force: Password Guessing' },
  passwordSpraying: { id: 'T1110.003', name: 'Brute Force: Password Spraying' },
  validAccounts: { id: 'T1078', name: 'Valid Accounts' },
  sudo: { id: 'T1548.003', name: 'Abuse Elevation Control: Sudo' },
  shadowFile: { id: 'T1003.008', name: 'OS Credential Dumping: /etc/passwd and /etc/shadow' },
  accountManipulation: { id: 'T1098', name: 'Account Manipulation' },
  createAccount: { id: 'T1136.001', name: 'Create Account: Local Account' },
  sshKeys: { id: 'T1098.004', name: 'Account Manipulation: SSH Authorized Keys' },
  cron: { id: 'T1053.003', name: 'Scheduled Task/Job: Cron' },
  clearLogs: { id: 'T1070.002', name: 'Indicator Removal: Clear Linux System Logs' },
  impairDefenses: { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools' },
  archive: { id: 'T1560.001', name: 'Archive Collected Data: Archive via Utility' },
  localData: { id: 'T1005', name: 'Data from Local System' },
  exfilAltProtocol: { id: 'T1048', name: 'Exfiltration Over Alternative Protocol' },
  wordlistScanning: { id: 'T1595.003', name: 'Active Scanning: Wordlist Scanning' },
  exploitPublicApp: { id: 'T1190', name: 'Exploit Public-Facing Application' },
  dataFromRepos: { id: 'T1213', name: 'Data from Information Repositories' },
};

export const RULE_MITRE = {
  brute_force: [T.passwordGuessing],
  password_spray: [T.passwordSpraying],
  compromised_login: [T.validAccounts],
  unusual_login: [T.validAccounts],
  sudo_denied: [T.sudo],
  recon_scan: [T.wordlistScanning],
  web_attack: [T.exploitPublicApp],
  data_exfiltration: [T.dataFromRepos],
};

// sudo / su commands -> technique (checked in order, all matches are kept)
export const COMMAND_MITRE = [
  { re: /\/etc\/shadow|\/etc\/passwd/, t: T.shadowFile },
  { re: /\/etc\/sudoers|visudo|usermod\s+.*-a?G|chmod\s+[ugo]*\+s|chmod\s+[0-7]?[4-7][0-7]{3}\s|\bsu\s+-?\s*root\b|\/bin\/(ba)?sh\s*$/, t: T.accountManipulation },
  { re: /\buseradd\b|\badduser\b/, t: T.createAccount },
  { re: /authorized_keys/, t: T.sshKeys },
  { re: /\bcrontab\b|\/etc\/cron/, t: T.cron },
  { re: /history\s+-c|(rm|shred|truncate).*\/var\/log|>\s*\/var\/log/, t: T.clearLogs },
  { re: /systemctl\s+(stop|disable)|iptables\s+-F|setenforce\s+0/, t: T.impairDefenses },
  { re: /\b(tar|zip)\b/, t: T.archive },
  { re: /mysqldump|pg_dump/, t: T.localData },
  { re: /\bscp\b|\brsync\b.*@|curl\s+.*(-T|--upload-file|-F|--data-binary)|\bnc\b/, t: T.exfilAltProtocol },
];

export function commandTechniques(commands) {
  const out = new Map();
  for (const cmd of commands) {
    for (const { re, t } of COMMAND_MITRE) if (re.test(cmd)) out.set(t.id, t);
  }
  return [...out.values()];
}
