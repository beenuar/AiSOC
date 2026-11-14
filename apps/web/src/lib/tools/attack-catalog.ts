/**
 * A compact, prevalence-ranked catalog of common MITRE ATT&CK (Enterprise)
 * techniques for the `/tools/coverage` grader.
 *
 * This is intentionally a curated high-signal subset (the techniques most SOCs
 * actually need coverage for), not the full ATT&CK matrix — the grader is a
 * quick self-check, not an authoritative audit. `prevalence` is a 1–100 rank
 * (higher = seen more often in real incidents) used to surface the top
 * highest-impact uncovered techniques. Kept honest: this is a heuristic ranking
 * for prioritization, documented as such on the tool page.
 */

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
  prevalence: number;
}

export const ATTACK_CATALOG: AttackTechnique[] = [
  { id: "T1566", name: "Phishing", tactic: "initial-access", prevalence: 98 },
  { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution", prevalence: 97 },
  { id: "T1059.001", name: "PowerShell", tactic: "execution", prevalence: 95 },
  { id: "T1078", name: "Valid Accounts", tactic: "defense-evasion", prevalence: 94 },
  { id: "T1486", name: "Data Encrypted for Impact", tactic: "impact", prevalence: 93 },
  { id: "T1055", name: "Process Injection", tactic: "defense-evasion", prevalence: 90 },
  { id: "T1003", name: "OS Credential Dumping", tactic: "credential-access", prevalence: 92 },
  { id: "T1021", name: "Remote Services", tactic: "lateral-movement", prevalence: 88 },
  { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "lateral-movement", prevalence: 82 },
  { id: "T1053", name: "Scheduled Task/Job", tactic: "persistence", prevalence: 85 },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tactic: "persistence", prevalence: 80 },
  { id: "T1071", name: "Application Layer Protocol", tactic: "command-and-control", prevalence: 84 },
  { id: "T1105", name: "Ingress Tool Transfer", tactic: "command-and-control", prevalence: 83 },
  { id: "T1567", name: "Exfiltration Over Web Service", tactic: "exfiltration", prevalence: 78 },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "exfiltration", prevalence: 74 },
  { id: "T1490", name: "Inhibit System Recovery", tactic: "impact", prevalence: 79 },
  { id: "T1112", name: "Modify Registry", tactic: "defense-evasion", prevalence: 76 },
  { id: "T1218", name: "System Binary Proxy Execution", tactic: "defense-evasion", prevalence: 77 },
  { id: "T1136", name: "Create Account", tactic: "persistence", prevalence: 70 },
  { id: "T1098", name: "Account Manipulation", tactic: "persistence", prevalence: 72 },
  { id: "T1110", name: "Brute Force", tactic: "credential-access", prevalence: 81 },
  { id: "T1082", name: "System Information Discovery", tactic: "discovery", prevalence: 68 },
  { id: "T1087", name: "Account Discovery", tactic: "discovery", prevalence: 66 },
  { id: "T1057", name: "Process Discovery", tactic: "discovery", prevalence: 64 },
  { id: "T1027", name: "Obfuscated Files or Information", tactic: "defense-evasion", prevalence: 75 },
  { id: "T1140", name: "Deobfuscate/Decode Files or Information", tactic: "defense-evasion", prevalence: 60 },
  { id: "T1204", name: "User Execution", tactic: "execution", prevalence: 86 },
  { id: "T1543", name: "Create or Modify System Process", tactic: "persistence", prevalence: 71 },
  { id: "T1562", name: "Impair Defenses", tactic: "defense-evasion", prevalence: 87 },
  { id: "T1070", name: "Indicator Removal", tactic: "defense-evasion", prevalence: 73 },
  { id: "T1036", name: "Masquerading", tactic: "defense-evasion", prevalence: 74 },
  { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "exfiltration", prevalence: 69 },
  { id: "T1090", name: "Proxy", tactic: "command-and-control", prevalence: 63 },
  { id: "T1573", name: "Encrypted Channel", tactic: "command-and-control", prevalence: 67 },
  { id: "T1195", name: "Supply Chain Compromise", tactic: "initial-access", prevalence: 62 },
  { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access", prevalence: 89 },
  { id: "T1133", name: "External Remote Services", tactic: "initial-access", prevalence: 79 },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "privilege-escalation", prevalence: 76 },
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "privilege-escalation", prevalence: 70 },
  { id: "T1552", name: "Unsecured Credentials", tactic: "credential-access", prevalence: 72 },
];

/** Fast lookup of parent technique id (T1059.001 → T1059). */
export function parentTechnique(id: string): string {
  const dot = id.indexOf(".");
  return dot > 0 ? id.slice(0, dot) : id;
}
