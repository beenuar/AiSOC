/**
 * packHelpers
 * ===========
 * Helpers for distinguishing AiSOC's shipped reference playbook packs from
 * user-created playbooks, deriving category facets, and forking a pack.
 *
 * Design notes:
 *   - The agents service loads both user-created playbooks and the
 *     `playbooks/packs/v1/**` reference packs into a single flat list at
 *     `GET /api/v1/playbooks` (see services/agents/app/playbook/store.py).
 *   - Shipped packs all carry `author === "AiSOC"` and use kebab-case ids
 *     like `supply-vendor-breach-v1`. User-created playbooks default to a
 *     UUID id (PlaybookStore.create generates one when id is empty).
 *   - We treat a playbook as a "pack" when the author matches AND the id
 *     does not look like a UUID. This avoids misclassifying any future
 *     user-submitted playbook that happens to set author="AiSOC".
 *   - Categories are recovered from the first matching tag — packs all
 *     prefix their tags with the category name (see playbooks/packs/v1).
 *   - MITRE tactics are inferred from `mitre.tXXXX` tags using the ATT&CK
 *     technique→tactic mapping. Techniques map to their primary tactic.
 *   - Severity is taken from trigger.severity (array of strings).
 *   - Integration filters are derived from step.type values, grouped into
 *     logical buckets (EDR, IAM, Ticketing, SIEM, Notify, AI, Firewall).
 */

import type { Playbook } from './types';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The 8 reference-pack categories shipped under playbooks/packs/v1. */
export const PACK_CATEGORIES = [
  'account-takeover',
  'cloud-misconfig',
  'data-exfil',
  'identity-compromise',
  'malware-detection',
  'network-anomaly',
  'ransomware',
  'supply-chain',
] as const;

export type PackCategory = (typeof PACK_CATEGORIES)[number];

const CATEGORY_LABELS: Record<PackCategory, string> = {
  'account-takeover': 'Account Takeover',
  'cloud-misconfig': 'Cloud Misconfig',
  'data-exfil': 'Data Exfil',
  'identity-compromise': 'Identity',
  'malware-detection': 'Malware',
  'network-anomaly': 'Network',
  ransomware: 'Ransomware',
  'supply-chain': 'Supply Chain',
};

const CATEGORY_COLORS: Record<PackCategory, string> = {
  'account-takeover':    'bg-orange-900/40 text-orange-300 border-orange-800',
  'cloud-misconfig':     'bg-cyan-900/40 text-cyan-300 border-cyan-800',
  'data-exfil':          'bg-pink-900/40 text-pink-300 border-pink-800',
  'identity-compromise': 'bg-blue-900/40 text-blue-300 border-blue-800',
  'malware-detection':   'bg-red-900/40 text-red-300 border-red-800',
  'network-anomaly':     'bg-teal-900/40 text-teal-300 border-teal-800',
  ransomware:            'bg-rose-900/40 text-rose-300 border-rose-800',
  'supply-chain':        'bg-amber-900/40 text-amber-300 border-amber-800',
};

/**
 * True when the playbook is one of the shipped reference packs that lives
 * under `playbooks/packs/v1/`. Heuristic: author "AiSOC" + non-UUID id.
 */
export function isShippedPack(pb: Playbook): boolean {
  if (pb.author !== 'AiSOC') return false;
  if (!pb.id) return false;
  return !UUID_REGEX.test(pb.id);
}

/**
 * Returns the pack category (account-takeover, ransomware, …) inferred
 * from the playbook's tags, or null when the playbook does not fit one
 * of the known categories.
 */
export function categoryOf(pb: Playbook): PackCategory | null {
  const tags = pb.tags ?? [];
  for (const tag of tags) {
    if ((PACK_CATEGORIES as readonly string[]).includes(tag)) {
      return tag as PackCategory;
    }
  }
  return null;
}

/** Human-readable label for a pack category. */
export function categoryLabel(cat: PackCategory): string {
  return CATEGORY_LABELS[cat];
}

/** Tailwind classes for a category badge. */
export function categoryBadgeClass(cat: PackCategory): string {
  return CATEGORY_COLORS[cat];
}

/** Source classification used by the gallery filter pills. */
export type PlaybookSource = 'all' | 'pack' | 'custom';

/* ─────────────────────────── MITRE Tactics ─────────────────────────── */

/**
 * The 12 MITRE ATT&CK tactics represented in the shipped packs.
 * Mapped from technique IDs found in `mitre.tXXXX` tags.
 */
export const MITRE_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const;

export type MitreTactic = (typeof MITRE_TACTICS)[number];

/**
 * Maps ATT&CK technique numeric prefix to its primary tactic.
 * Covers all techniques present in playbooks/packs/v1.
 */
const TECHNIQUE_TACTIC_MAP: Record<number, MitreTactic> = {
  1021:  'Lateral Movement',       // Remote Services
  1041:  'Exfiltration',           // Exfiltration Over C2
  1046:  'Discovery',              // Network Service Discovery
  1048:  'Exfiltration',           // Exfiltration Over Alt Protocol
  1052:  'Exfiltration',           // Exfiltration Over Physical Medium
  1059:  'Execution',              // Command & Scripting Interpreter
  1068:  'Privilege Escalation',   // Exploitation for Priv Esc
  1071:  'Command and Control',    // App Layer Protocol
  1078:  'Initial Access',         // Valid Accounts
  1110:  'Credential Access',      // Brute Force
  1134:  'Privilege Escalation',   // Access Token Manipulation
  1190:  'Initial Access',         // Exploit Public-Facing App
  1195:  'Initial Access',         // Supply Chain Compromise
  1199:  'Initial Access',         // Trusted Relationship
  1204:  'Execution',              // User Execution
  1486:  'Impact',                 // Data Encrypted for Impact
  1490:  'Impact',                 // Inhibit System Recovery
  1498:  'Impact',                 // Network Denial of Service
  1505:  'Persistence',            // Server Software Component
  1528:  'Credential Access',      // Steal Application Access Token
  1530:  'Collection',             // Data from Cloud Storage
  1535:  'Defense Evasion',        // Unused/Unsupported Cloud Regions
  1539:  'Credential Access',      // Steal Web Session Cookie
  1548:  'Privilege Escalation',   // Abuse Elevation Control
  1550:  'Defense Evasion',        // Use Alt Auth Material
  1552:  'Credential Access',      // Unsecured Credentials
  1621:  'Credential Access',      // MFA Request Generation
};

/**
 * Extracts the MITRE tactics for a playbook by parsing `mitre.tXXXX` tags
 * and looking them up in the technique→tactic map.
 */
export function mitreTacticsOf(pb: Playbook): MitreTactic[] {
  const tactics = new Set<MitreTactic>();
  for (const tag of pb.tags ?? []) {
    const m = tag.match(/^mitre\.t(\d+)/i);
    if (!m) continue;
    const num = parseInt(m[1], 10);
    const tactic = TECHNIQUE_TACTIC_MAP[num];
    if (tactic) tactics.add(tactic);
  }
  return Array.from(tactics);
}

/* ─────────────────────────── Severity ─────────────────────────── */

export const SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type SeverityLevel = (typeof SEVERITY_LEVELS)[number];

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  info:     'bg-blue-900/40 text-blue-300 border-blue-800',
  low:      'bg-gray-800/60 text-gray-400 border-gray-700',
  medium:   'bg-yellow-900/40 text-yellow-300 border-yellow-800',
  high:     'bg-orange-900/40 text-orange-300 border-orange-800',
  critical: 'bg-red-900/40 text-red-300 border-red-800',
};

export function severityBadgeClass(sev: SeverityLevel): string {
  return SEVERITY_COLORS[sev];
}

/**
 * Returns the severity levels a playbook is triggered by.
 */
export function severitiesOf(pb: Playbook): SeverityLevel[] {
  const raw = pb.trigger?.severity ?? [];
  return raw.filter((s): s is SeverityLevel =>
    (SEVERITY_LEVELS as readonly string[]).includes(s),
  );
}

/* ─────────────────────────── Integrations ─────────────────────────── */

/**
 * Integration buckets — derived from step `type` values.
 * Each bucket maps to one or more raw step types.
 */
export const INTEGRATION_TYPES = [
  'AI Analysis',
  'EDR / Endpoint',
  'Identity / IAM',
  'Ticketing',
  'SIEM',
  'Notification',
  'Firewall / Network',
  'HTTP / Custom',
] as const;

export type IntegrationType = (typeof INTEGRATION_TYPES)[number];

const STEP_TYPE_TO_INTEGRATION: Record<string, IntegrationType> = {
  investigate:         'AI Analysis',
  enrich:              'AI Analysis',
  isolate_host:        'EDR / Endpoint',
  quarantine_file:     'EDR / Endpoint',
  kill_process:        'EDR / Endpoint',
  run_av_scan:         'EDR / Endpoint',
  run_script:          'EDR / Endpoint',
  disable_user:        'Identity / IAM',
  reset_password:      'Identity / IAM',
  revoke_session:      'Identity / IAM',
  force_mfa:           'Identity / IAM',
  create_ticket:       'Ticketing',
  search_siem:         'SIEM',
  create_notable_event:'SIEM',
  notify:              'Notification',
  block_ip:            'Firewall / Network',
  block_ioc:           'Firewall / Network',
  http:                'HTTP / Custom',
};

/**
 * Returns the set of integration types used by a playbook's steps.
 */
export function integrationsOf(pb: Playbook): IntegrationType[] {
  const types = new Set<IntegrationType>();
  for (const step of pb.steps ?? []) {
    const bucket = STEP_TYPE_TO_INTEGRATION[step.type];
    if (bucket) types.add(bucket);
  }
  return Array.from(types);
}

/* ─────────────────────────── Filter ─────────────────────────── */

/** Apply gallery filters (source + category + MITRE + severity + integration + search). */
export function filterPlaybooks(
  playbooks: Playbook[],
  filters: {
    source: PlaybookSource;
    category: PackCategory | 'all';
    mitreTactic?: MitreTactic | 'all';
    severity?: SeverityLevel | 'all';
    integration?: IntegrationType | 'all';
    search: string;
  },
): Playbook[] {
  const {
    mitreTactic = 'all',
    severity = 'all',
    integration = 'all',
  } = filters;
  const q = filters.search.trim().toLowerCase();
  return playbooks.filter((pb) => {
    const isPack = isShippedPack(pb);
    if (filters.source === 'pack' && !isPack) return false;
    if (filters.source === 'custom' && isPack) return false;
    if (filters.category !== 'all') {
      const cat = categoryOf(pb);
      if (cat !== filters.category) return false;
    }
    if (mitreTactic !== 'all') {
      const tactics = mitreTacticsOf(pb);
      if (!tactics.includes(mitreTactic)) return false;
    }
    if (severity !== 'all') {
      const sevs = severitiesOf(pb);
      if (!sevs.includes(severity)) return false;
    }
    if (integration !== 'all') {
      const integrations = integrationsOf(pb);
      if (!integrations.includes(integration)) return false;
    }
    if (q) {
      const haystack = [pb.name, pb.description, ...(pb.tags ?? [])]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

/**
 * Counts of playbooks per source bucket (used to render the source pills).
 */
export function countBySource(playbooks: Playbook[]): { all: number; pack: number; custom: number } {
  let pack = 0;
  let custom = 0;
  for (const pb of playbooks) {
    if (isShippedPack(pb)) pack += 1;
    else custom += 1;
  }
  return { all: playbooks.length, pack, custom };
}

/**
 * Counts of pack playbooks per category (used to render the category pills).
 */
export function countByCategory(playbooks: Playbook[]): Record<PackCategory, number> {
  const out: Record<PackCategory, number> = {
    'account-takeover': 0,
    'cloud-misconfig': 0,
    'data-exfil': 0,
    'identity-compromise': 0,
    'malware-detection': 0,
    'network-anomaly': 0,
    'ransomware': 0,
    'supply-chain': 0,
  };
  for (const pb of playbooks) {
    const cat = categoryOf(pb);
    if (cat) out[cat] += 1;
  }
  return out;
}

/**
 * Build the JSON body for forking a shipped pack into a user-owned copy.
 * The agents service generates a fresh UUID when `id` is empty (see
 * PlaybookStore.create). We disable the fork by default so it doesn't
 * fire on the next matching alert before the operator reviews it.
 */
export function buildForkBody(original: Playbook, opts?: { author?: string }): Playbook {
  return {
    ...original,
    id: '',
    name: `${original.name} (fork)`,
    author: opts?.author ?? 'you',
    enabled: false,
    tags: Array.from(new Set([...(original.tags ?? []), `fork-of:${original.id}`])),
    created_at: '',
    updated_at: '',
  };
}

/**
 * POST a forked playbook to the agents API. Returns the created Playbook
 * (with a freshly assigned UUID) or throws on failure.
 */
export async function forkPlaybook(
  original: Playbook,
  opts?: { author?: string },
): Promise<Playbook> {
  const body = buildForkBody(original, opts);
  const res = await fetch('/api/v1/playbooks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Fork failed: HTTP ${res.status}${text ? ` — ${text}` : ''}`);
  }
  return (await res.json()) as Playbook;
}
