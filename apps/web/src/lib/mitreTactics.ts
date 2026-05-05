/**
 * MITRE ATT&CK tactic mapping for technique IDs.
 *
 * The full ATT&CK Enterprise corpus is large; this file maintains a curated
 * map covering the techniques AiSOC ships rules for today, plus the parent
 * technique for every sub-technique we know about. Anything outside the map
 * falls back to the "Other" bucket so the coverage view still degrades
 * gracefully if upstream importers introduce a technique we haven't mapped
 * yet.
 *
 * Source of truth: https://attack.mitre.org/matrices/enterprise/ (Apr 2026
 * snapshot). When new techniques land, add them here so they show up in the
 * right tactic column.
 */

export interface Tactic {
  id: string;
  name: string;
  shortName: string;
}

/** ATT&CK Enterprise tactics, in standard kill-chain order. */
export const TACTICS: Tactic[] = [
  { id: 'TA0043', name: 'Reconnaissance', shortName: 'Recon' },
  { id: 'TA0042', name: 'Resource Development', shortName: 'Resource Dev' },
  { id: 'TA0001', name: 'Initial Access', shortName: 'Init Access' },
  { id: 'TA0002', name: 'Execution', shortName: 'Execution' },
  { id: 'TA0003', name: 'Persistence', shortName: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation', shortName: 'Priv Esc' },
  { id: 'TA0005', name: 'Defense Evasion', shortName: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access', shortName: 'Cred Access' },
  { id: 'TA0007', name: 'Discovery', shortName: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement', shortName: 'Lateral' },
  { id: 'TA0009', name: 'Collection', shortName: 'Collection' },
  { id: 'TA0011', name: 'Command and Control', shortName: 'C&C' },
  { id: 'TA0010', name: 'Exfiltration', shortName: 'Exfil' },
  { id: 'TA0040', name: 'Impact', shortName: 'Impact' },
];

export const TACTIC_BY_ID = new Map<string, Tactic>(
  TACTICS.map((t) => [t.id, t]),
);

const OTHER_TACTIC_ID = 'OTHER';

export const OTHER_TACTIC: Tactic = {
  id: OTHER_TACTIC_ID,
  name: 'Other / Unmapped',
  shortName: 'Other',
};

/**
 * Parent-technique → tactic IDs.
 *
 * Sub-techniques (e.g. T1078.001) inherit the parent's tactics unless they
 * appear here explicitly. This keeps the table small while still routing the
 * 120+ technique IDs we ship today into the right columns.
 */
const PARENT_TACTIC_MAP: Record<string, string[]> = {
  // Reconnaissance
  T1592: ['TA0043'],
  T1595: ['TA0043'],

  // Initial Access
  T1133: ['TA0001', 'TA0003'],
  T1190: ['TA0001'],
  T1195: ['TA0001'],
  T1199: ['TA0001'],
  T1566: ['TA0001'],
  T1656: ['TA0001'],

  // Execution
  T1047: ['TA0002'],
  T1059: ['TA0002'],
  T1204: ['TA0002'],
  T1609: ['TA0002'],

  // Persistence
  T1098: ['TA0003', 'TA0004'],
  T1136: ['TA0003'],
  T1176: ['TA0003'],
  T1505: ['TA0003'],
  T1525: ['TA0003'],

  // Privilege Escalation
  T1068: ['TA0004'],
  T1611: ['TA0004'],

  // Multi-tactic
  T1053: ['TA0002', 'TA0003', 'TA0004'],
  T1055: ['TA0004', 'TA0005'],
  T1078: ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
  T1543: ['TA0003', 'TA0004'],
  T1547: ['TA0003', 'TA0004'],
  T1548: ['TA0004', 'TA0005'],
  T1574: ['TA0003', 'TA0004', 'TA0005'],
  T1484: ['TA0004', 'TA0005'],

  // Defense Evasion
  T1027: ['TA0005'],
  T1070: ['TA0005'],
  T1218: ['TA0005'],
  T1550: ['TA0005', 'TA0008'],
  T1553: ['TA0005'],
  T1556: ['TA0003', 'TA0005', 'TA0006'],
  T1562: ['TA0005'],
  T1564: ['TA0005'],
  T1578: ['TA0005'],

  // Credential Access
  T1003: ['TA0006'],
  T1110: ['TA0006'],
  T1212: ['TA0006'],
  T1528: ['TA0006'],
  T1539: ['TA0006'],
  T1552: ['TA0006'],
  T1555: ['TA0006'],
  T1557: ['TA0006', 'TA0009'],
  T1558: ['TA0006'],
  T1606: ['TA0006'],
  T1621: ['TA0006'],

  // Discovery
  T1040: ['TA0006', 'TA0007'],
  T1046: ['TA0007'],
  T1069: ['TA0007'],
  T1083: ['TA0007'],
  T1087: ['TA0007'],
  T1135: ['TA0007'],

  // Lateral Movement
  T1021: ['TA0008'],

  // Collection
  T1113: ['TA0009'],
  T1114: ['TA0009'],
  T1530: ['TA0009'],
  T1560: ['TA0009'],

  // Command and Control
  T1071: ['TA0011'],
  T1090: ['TA0011'],
  T1095: ['TA0011'],
  T1219: ['TA0011'],
  T1568: ['TA0011'],
  T1572: ['TA0011'],
  T1573: ['TA0011'],

  // Exfiltration
  T1041: ['TA0010'],
  T1048: ['TA0010'],
  T1052: ['TA0010'],
  T1567: ['TA0010'],

  // Impact
  T1485: ['TA0040'],
  T1486: ['TA0040'],
  T1490: ['TA0040'],
  T1498: ['TA0040'],
  T1531: ['TA0040'],
  T1565: ['TA0040'],
};

/**
 * Resolve the tactics this technique covers.
 *
 * Sub-techniques (T1078.004) inherit from their parent (T1078) unless they
 * override the mapping. Returns ``[OTHER_TACTIC.id]`` if the technique is not
 * known so unmapped rules still get counted in the matrix instead of falling
 * off the bottom of the page.
 */
export function tacticsFor(techniqueId: string): string[] {
  const direct = PARENT_TACTIC_MAP[techniqueId];
  if (direct) return direct;
  const parent = techniqueId.split('.')[0];
  const fallback = PARENT_TACTIC_MAP[parent];
  if (fallback) return fallback;
  return [OTHER_TACTIC_ID];
}

/** Return the parent technique id for a sub-technique, or itself otherwise. */
export function parentTechnique(techniqueId: string): string {
  return techniqueId.split('.')[0];
}
