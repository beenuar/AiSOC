/**
 * Turning a SIEM row into a pivot the console can actually service.
 *
 * Federated rows arrive in whatever shape the vendor emits — Splunk's `src`,
 * Sentinel's `SourceIP`, Elastic's `source.ip`. To offer a pivot we have to
 * recognise the entity inside the row first, and we only claim a pivot for the
 * field names we genuinely recognise. An unrecognised column renders as plain
 * text rather than a link that lands somewhere unhelpful.
 *
 * The target is `/graph?entity=<type>:<value>`, which is the URL shape the
 * Investigation Rail's entity chips already use (`services/api/app/services/
 * alert_rail.py` builds `entity=host:…`, `entity=ip:…`). `AttackGraphView`
 * reads and honours that parameter, so these links select the node rather than
 * merely landing on the page.
 */

export type PivotEntityType = 'host' | 'user' | 'ip' | 'domain';

export interface PivotTarget {
  type: PivotEntityType;
  value: string;
}

/**
 * Field names, lower-cased, that carry each entity type.
 *
 * Deliberately a fixed list rather than a heuristic. A regex that guesses
 * "anything containing `ip`" also matches `zip`, `recipient` and `description`,
 * and a pivot on the wrong entity is worse than no pivot: it silently widens
 * the analyst's picture with an unrelated node.
 */
const FIELD_MAP: ReadonlyArray<readonly [PivotEntityType, ReadonlySet<string>]> = [
  [
    'host',
    new Set([
      'host',
      'hostname',
      'host.name',
      'computer',
      'computername',
      'device.name',
      'dvc',
      'machine',
      'src_host',
      'agent.name',
    ]),
  ],
  [
    'user',
    new Set([
      'user',
      'username',
      'user.name',
      'user_name',
      'account',
      'accountname',
      'actor.user.name',
      'subjectusername',
      'samaccountname',
    ]),
  ],
  [
    'ip',
    new Set([
      'ip',
      'src',
      'src_ip',
      'source.ip',
      'sourceip',
      'client_ip',
      'clientip',
      'dest',
      'dest_ip',
      'destination.ip',
      'destinationip',
      'src_endpoint.ip',
      'remote_ip',
    ]),
  ],
  [
    'domain',
    new Set([
      'domain',
      'dns.question.name',
      'query',
      'fqdn',
      'url_domain',
      'dest_host',
      'http_host',
    ]),
  ],
];

/** Longest value we will put in a URL. Beyond this it is not an identifier. */
const MAX_PIVOT_VALUE = 255;

function normaliseValue(raw: unknown): string | null {
  if (typeof raw === 'number') return String(raw);
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (trimmed === '' || trimmed.length > MAX_PIVOT_VALUE) return null;
  // Placeholders several vendors emit for "field present but unset". Linking
  // on these produces a pivot to a node that cannot exist.
  if (['-', 'null', 'none', 'n/a', 'unknown', '(null)'].includes(trimmed.toLowerCase())) {
    return null;
  }
  return trimmed;
}

/**
 * Entities worth pivoting on in one row, de-duplicated by `type:value`.
 *
 * Capped, because a wide SIEM row can carry a dozen recognised columns and a
 * row of twelve pivot chips is not a pivot affordance, it is noise.
 */
export function pivotableFields(
  fields: Record<string, unknown>,
  max = 4,
): PivotTarget[] {
  const seen = new Set<string>();
  const out: PivotTarget[] = [];

  for (const [key, raw] of Object.entries(fields)) {
    const lower = key.toLowerCase();
    const match = FIELD_MAP.find(([, names]) => names.has(lower));
    if (!match) continue;

    const value = normaliseValue(raw);
    if (value === null) continue;

    const dedupeKey = `${match[0]}:${value.toLowerCase()}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({ type: match[0], value });

    if (out.length >= max) break;
  }

  return out;
}

/** `/graph?entity=<type>:<value>`, with the value encoded exactly once. */
export function pivotPathForValue(type: PivotEntityType, value: string): string {
  return `/graph?entity=${encodeURIComponent(`${type}:${value}`)}`;
}
