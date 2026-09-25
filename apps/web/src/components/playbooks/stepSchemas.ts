/**
 * stepSchemas
 * ===========
 *
 * The editor's single registry of the playbook step vocabulary: what each
 * step type is called, what the engine does with it, and what its parameters
 * are.
 *
 * Single, now. It used to be one of five vocabularies. The engine
 * (`services/agents/app/playbook/models.py`) declares twenty-two step types
 * and the published package (`packages/types/src/playbook.ts`) publishes the
 * same twenty-two, but this directory declared its own nine-member union in
 * `./types` and keyed `STEP_SCHEMAS` on *that* — so `Record<StepType, …>` was
 * satisfied with thirteen forms missing and the build stayed green. Keying it
 * on the published union is what makes the compiler enumerate a new verb
 * instead of a reviewer having to.
 *
 * `stepColors`, the editor palette and the inspector's type dropdown are all
 * derived from this map rather than restating it, and
 * `scripts/check_playbook_schema_parity.py` reads it against the engine and
 * the schema in both directions. A sixth vocabulary is a failed build.
 *
 * Two conventions live here, and the difference is worth knowing
 * -------------------------------------------------------------
 * The nine original forms collect `*_field` keys — `ip_field`,
 * `host_field`, `case_id_field`. The engine does **not** dereference those:
 * `_resolve_target` and the `enrich` / `investigate` handlers read fixed keys
 * (`ip`, `src_ip`, `host`, `case_id`, …) from `step.params` first and the
 * trigger context second. `*_field` is an authoring convention that the 833
 * steps in `playbooks/packs/v1` are written in, and those steps run because
 * the alert context supplies the value — not because the parameter is read.
 * Changing it means changing the engine or the packs, neither of which is
 * this file's to change, so the nine are left as they are.
 *
 * The thirteen added here write the keys the engine and the executor actually
 * read, and each target field's help text names the fallback chain
 * `_resolve_target` implements. Where a parameter is inert, it is not offered:
 * the shipped packs carry a `dry_run` param on response steps and nothing
 * reads it — whether a vendor is touched is decided by
 * `AISOC_PLAYBOOK_ACTIONS_EXECUTE` and the capability contract — so there is
 * no `dry_run` control here rather than a checkbox that does nothing.
 *
 * Credentials are never collected. `services/api` resolves them per tenant
 * from the connector vault at dispatch time; a form asking for
 * `cs_client_secret` would be asking an author to paste a secret into a
 * playbook document.
 */

import type { StepExecution, StepType } from './types';

export type FieldKind =
  | 'string'
  | 'textarea'
  | 'number'
  | 'boolean'
  | 'select'
  | 'env_ref'
  | 'jsonpath'
  | 'string_list';

export interface FieldOption {
  value: string;
  label: string;
}

export interface FieldDescriptor {
  /** Param key (object key inside step.params). */
  key: string;
  /** Human label rendered as the form label. */
  label: string;
  kind: FieldKind;
  /** True if leaving the field empty should fail validation on save. */
  required?: boolean;
  /** Placeholder for string-y inputs. */
  placeholder?: string;
  /** Subtle help text rendered under the field. */
  help?: string;
  /** For select kinds. */
  options?: readonly FieldOption[];
  /** Optional default applied when a step is created. */
  defaultValue?: unknown;
}

export interface StepSchema {
  type: StepType;
  /**
   * What the engine does with this type, mirroring the schema's
   * `x-aisoc-execution` map — which the parity gate compares against the
   * engine's real handler table, so it cannot become an aspirational claim.
   *
   * - `executed` — a handler runs and has a real effect.
   * - `governed` — dispatched to `services/actions`, where the capability
   *   contract and the tenant's autonomy policy decide whether a vendor is
   *   touched. Reaching dispatch is not executing; the run's own report says
   *   which happened.
   * - `unimplemented` — no handler. The engine fails the step closed and the
   *   default `on_failure: abort` halts the run.
   */
  execution: StepExecution;
  label: string;
  description: string;
  /** Pretty colour token used in the canvas / palette. */
  accent: string;
  /** Canvas node background. */
  bgColor: string;
  /** Single-emoji icon used in the palette. */
  icon: string;
  /** Short badge rendered on the canvas node, where an emoji is too wide. */
  shortCode: string;
  fields: readonly FieldDescriptor[];
  /**
   * Why this type cannot run, in the engine's own words. Set on every
   * `unimplemented` type and on no other, so the UI can explain rather than
   * offer. See `_UNBRIDGEABLE` in `services/agents/app/playbook/engine.py`.
   */
  unavailable?: string;
}

const NOTIFY_CHANNELS: readonly FieldOption[] = [
  { value: 'slack', label: 'Slack' },
  { value: 'pagerduty', label: 'PagerDuty' },
  { value: 'email', label: 'Email' },
  { value: 'webhook', label: 'Generic webhook' },
];

const TICKET_PRIORITIES: readonly FieldOption[] = [
  { value: 'P1', label: 'P1 — Critical' },
  { value: 'P2', label: 'P2 — High' },
  { value: 'P3', label: 'P3 — Medium' },
  { value: 'P4', label: 'P4 — Low' },
];

const HTTP_METHODS: readonly FieldOption[] = [
  { value: 'GET', label: 'GET' },
  { value: 'POST', label: 'POST' },
  { value: 'PUT', label: 'PUT' },
  { value: 'PATCH', label: 'PATCH' },
  { value: 'DELETE', label: 'DELETE' },
];

const INVESTIGATE_FOCUS: readonly FieldOption[] = [
  { value: 'forensics', label: 'Forensics' },
  { value: 'identity', label: 'Identity' },
  { value: 'network', label: 'Network' },
  { value: 'cloud', label: 'Cloud' },
  { value: 'malware', label: 'Malware' },
];

/** Defender's indicator vocabulary, from `BlockIOCExecutor`. */
const IOC_TYPES: readonly FieldOption[] = [
  { value: 'IpAddress', label: 'IP address' },
  { value: 'DomainName', label: 'Domain name' },
  { value: 'Url', label: 'URL' },
  { value: 'FileSha256', label: 'File hash — SHA256' },
  { value: 'FileSha1', label: 'File hash — SHA1' },
];

/** The platform's five-tier ladder, as `CreateNotableEventExecutor` reads it. */
const SEVERITIES: readonly FieldOption[] = [
  { value: 'info', label: 'Info' },
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
];

const OSQUERY_BACKENDS: readonly FieldOption[] = [
  { value: 'osctrl', label: 'osctrl' },
  { value: 'fleetdm', label: 'FleetDM' },
  { value: 'aisoc_direct', label: 'AiSOC direct' },
];

const AV_SCAN_TYPES: readonly FieldOption[] = [
  { value: 'Quick', label: 'Quick' },
  { value: 'Full', label: 'Full' },
];

/**
 * The target a response verb acts on, keyed on the first name
 * `engine._TARGET_KEYS` looks for. Left blank, the engine falls back to the
 * remaining names in `step.params` and then to the trigger context — which is
 * how a playbook says "the host in this alert" rather than a fixed one.
 */
function target(
  key: string,
  label: string,
  placeholder: string,
  fallbacks: readonly string[],
): FieldDescriptor {
  const names = [key, ...fallbacks].join(', ');
  return {
    key,
    label,
    kind: 'string',
    placeholder,
    help: `Leave blank to take ${names} from the triggering alert instead.`,
  };
}

const HOST_TARGET = target('host', 'Host', 'web-prod-04', [
  'hostname',
  'device_id',
  'host_id',
]);

const USER_TARGET = target('user', 'User', 'jane.doe@example.com', [
  'username',
  'user_id',
  'upn',
  'email',
]);

export const STEP_SCHEMAS: Record<StepType, StepSchema> = {
  enrich: {
    type: 'enrich',
    execution: 'executed',
    label: 'Enrich',
    description: 'Look up additional context for an indicator (IP, hash, user, asset).',
    accent: '#38bdf8',
    bgColor: '#1a3040',
    icon: '🔍',
    shortCode: 'enr',
    fields: [
      {
        key: 'indicator_field',
        label: 'Indicator field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.src_ip',
        help: 'JSON path on the alert/case context to enrich.',
      },
    ],
  },
  investigate: {
    type: 'investigate',
    execution: 'executed',
    label: 'Investigate',
    description: 'Run the investigator agent against a case to gather artefacts and timeline.',
    accent: '#a78bfa',
    bgColor: '#2e1f5e',
    icon: '🕵️',
    shortCode: 'inv',
    fields: [
      {
        key: 'case_id_field',
        label: 'Case ID field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.case_id',
      },
      {
        key: 'focus',
        label: 'Focus',
        kind: 'select',
        options: INVESTIGATE_FOCUS,
        help: 'Optional bias for what artefacts to pull first.',
      },
    ],
  },
  notify: {
    type: 'notify',
    execution: 'executed',
    label: 'Notify',
    description: 'Send a notification to Slack, PagerDuty, email, or a generic webhook.',
    accent: '#facc15',
    bgColor: '#1a3d2e',
    icon: '🔔',
    shortCode: 'ntf',
    fields: [
      {
        key: 'channel',
        label: 'Channel',
        kind: 'select',
        required: true,
        options: NOTIFY_CHANNELS,
        defaultValue: 'slack',
      },
      {
        key: 'message_template',
        label: 'Message template',
        kind: 'textarea',
        required: true,
        placeholder: 'Lateral movement detected on {{alert.host}}',
        help: 'Mustache-style template; fields from alert/case are interpolated at runtime.',
      },
      {
        key: 'service_key_env',
        label: 'PagerDuty service key env',
        kind: 'env_ref',
        placeholder: 'PD_SOC_KEY',
        help: 'Required only for the PagerDuty channel.',
      },
      {
        key: 'webhook_env',
        label: 'Webhook URL env',
        kind: 'env_ref',
        placeholder: 'SOC_WEBHOOK_URL',
        help: 'Required only for the generic webhook channel.',
      },
    ],
  },
  block_ip: {
    type: 'block_ip',
    execution: 'governed',
    label: 'Block IP',
    description: 'Push a blocklist rule into the network executor (firewall / WAF / cloud SG).',
    accent: '#f87171',
    bgColor: '#3d1a1a',
    icon: '🚫',
    shortCode: 'blk',
    fields: [
      {
        key: 'ip_field',
        label: 'IP address field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.src_ip',
      },
      {
        key: 'duration',
        label: 'Duration (seconds)',
        kind: 'number',
        required: true,
        defaultValue: 3600,
        help: 'How long the block should remain in place. Use 0 for permanent.',
      },
    ],
  },
  block_ioc: {
    type: 'block_ioc',
    execution: 'governed',
    label: 'Block IOC',
    description:
      'Add an indicator — hash, domain, URL or address — to the EDR blocklist. Breadth depends on the indicator type, so the contract grades it at the worst case.',
    accent: '#ef4444',
    bgColor: '#3d1a1a',
    icon: '⛔',
    shortCode: 'ioc',
    fields: [
      target('ioc', 'Indicator', '203.0.113.10', ['indicator', 'hash', 'domain', 'ip']),
      {
        key: 'ioc_type',
        label: 'Indicator type',
        kind: 'select',
        required: true,
        options: IOC_TYPES,
        defaultValue: 'IpAddress',
        help: 'Must match the indicator: blocking a SHA256 as an IP address is rejected by the vendor.',
      },
      {
        key: 'title',
        label: 'Blocklist entry title',
        kind: 'string',
        placeholder: 'C2 infrastructure — campaign RAVEN',
        help: 'Shown in the vendor console. Defaults to "AiSOC — blocked <type>: <indicator>".',
      },
    ],
  },
  isolate_host: {
    type: 'isolate_host',
    execution: 'governed',
    label: 'Isolate host',
    description: 'Quarantine an endpoint via the EDR (CrowdStrike, Defender, etc.).',
    accent: '#fb7185',
    bgColor: '#3d2a1a',
    icon: '🛡️',
    shortCode: 'iso',
    fields: [
      {
        key: 'host_field',
        label: 'Host field',
        kind: 'jsonpath',
        required: true,
        placeholder: 'alert.host',
      },
    ],
  },
  create_ticket: {
    type: 'create_ticket',
    execution: 'governed',
    label: 'Create ticket',
    description: 'Open a Jira / ServiceNow ticket for SOC follow-up.',
    accent: '#34d399',
    bgColor: '#3d341a',
    icon: '📝',
    shortCode: 'tkt',
    fields: [
      {
        key: 'priority',
        label: 'Priority',
        kind: 'select',
        required: true,
        options: TICKET_PRIORITIES,
        defaultValue: 'P2',
      },
      {
        key: 'queue',
        label: 'Queue',
        kind: 'string',
        required: true,
        placeholder: 'soc',
        defaultValue: 'soc',
      },
      {
        key: 'title_template',
        label: 'Title template',
        kind: 'string',
        required: true,
        placeholder: 'Lateral movement: {{alert.src_host}} -> {{alert.dst_host}}',
      },
    ],
  },
  close_case: {
    type: 'close_case',
    execution: 'executed',
    label: 'Close case',
    description: 'Mark the case resolved. Terminal step — no outgoing edges allowed.',
    accent: '#94a3b8',
    bgColor: '#252d3a',
    icon: '✅',
    shortCode: 'cls',
    fields: [
      {
        key: 'resolution',
        label: 'Resolution',
        kind: 'select',
        required: true,
        options: [
          { value: 'true_positive_contained', label: 'True positive — contained' },
          { value: 'true_positive_remediated', label: 'True positive — remediated' },
          { value: 'false_positive', label: 'False positive' },
          { value: 'benign', label: 'Benign / expected' },
          { value: 'duplicate', label: 'Duplicate' },
        ],
        defaultValue: 'true_positive_contained',
      },
    ],
  },
  http: {
    type: 'http',
    execution: 'executed',
    label: 'HTTP request',
    description: 'Generic outbound HTTP — useful for arbitrary integrations.',
    accent: '#60a5fa',
    bgColor: '#1a3040',
    icon: '🌐',
    shortCode: 'http',
    fields: [
      {
        key: 'method',
        label: 'Method',
        kind: 'select',
        required: true,
        options: HTTP_METHODS,
        defaultValue: 'POST',
      },
      {
        key: 'url',
        label: 'URL',
        kind: 'string',
        required: true,
        placeholder: 'https://example.com/api/notify',
      },
      {
        key: 'headers_env',
        label: 'Headers env',
        kind: 'env_ref',
        placeholder: 'INTEGRATION_HEADERS',
        help: 'Optional. Env var holding a JSON-encoded headers object.',
      },
      {
        key: 'body_template',
        label: 'Body template',
        kind: 'textarea',
        placeholder: '{"text": "Alert {{alert.id}}"}',
        help: 'Optional. Mustache-style template for the request body.',
      },
    ],
  },
  condition: {
    type: 'condition',
    execution: 'executed',
    label: 'Condition',
    description:
      'Branch the playbook on a field check. Configure the predicate via the Condition section above.',
    accent: '#fbbf24',
    bgColor: '#3a1a40',
    icon: '❓',
    shortCode: 'if',
    // condition has no params — its predicate lives on `step.condition`.
    fields: [],
  },
  osquery_live_query: {
    type: 'osquery_live_query',
    execution: 'executed',
    label: 'Live query',
    description:
      'Run an allowlisted osquery query across hosts through osctrl, FleetDM or the AiSOC agent. The query itself is a template ID, not free SQL, so a playbook cannot ask an endpoint an arbitrary question. Needs an agents image carrying the osquery backend clients; without them the engine fails the step rather than reporting a query it never sent.',
    accent: '#2dd4bf',
    bgColor: '#123333',
    icon: '🔎',
    shortCode: 'osq',
    fields: [
      {
        key: 'template',
        label: 'Query template',
        kind: 'string',
        required: true,
        placeholder: 'running_processes',
        help: 'Allowlist template ID. The engine refuses the step without one.',
      },
      {
        key: 'backend',
        label: 'Backend',
        kind: 'select',
        required: true,
        options: OSQUERY_BACKENDS,
        defaultValue: 'osctrl',
      },
      {
        key: 'target_hosts',
        label: 'Target hosts',
        kind: 'string_list',
        placeholder: 'web-prod-04, web-prod-05',
        help: 'Comma-separated host UUIDs or names. Leave blank to query the host named in the alert.',
      },
      {
        key: 'instance_id',
        label: 'Connector instance',
        kind: 'string',
        placeholder: 'a1b2c3d4-…',
        help:
          'Connector instance whose credentials the backend should use. Leave blank to use ' +
          '`connector_instance_id` from the alert. Credentials are read from the vault, never from this playbook.',
      },
      {
        key: 'timeout_seconds',
        label: 'Collection window (seconds)',
        kind: 'number',
        defaultValue: 60,
        help: 'How long to wait for hosts to answer. Clamped to the engine ceiling of 3600.',
      },
    ],
  },
  approval: {
    type: 'approval',
    execution: 'unimplemented',
    label: 'Approval',
    description:
      'Not runnable. The engine fails an approval step closed and the run stops there.',
    accent: '#64748b',
    bgColor: '#1e232b',
    icon: '⛔',
    shortCode: 'appr',
    fields: [],
    unavailable:
      'An approval step is a pause, and the engine is a single-threaded index walk with no pause ' +
      'or resume — there is nothing to suspend and nothing to wake. It is also no longer the ' +
      'mechanism: every response step is graded against its own capability contract at dispatch ' +
      'and returns "pending approval" on its own when a human is required, so an approval step in ' +
      'front of one would gate a decision that is already gated. Remove it, or hold the action in ' +
      'the actions service, which does queue for an analyst.',
  },
  disable_user: {
    type: 'disable_user',
    execution: 'governed',
    label: 'Disable user',
    description:
      'Disable an account in Okta, Entra or Google Workspace. Stops one person working; reversible, and instantly noticed.',
    accent: '#fb923c',
    bgColor: '#3d2a1a',
    icon: '🔒',
    shortCode: 'dis',
    fields: [USER_TARGET],
  },
  reset_password: {
    type: 'reset_password',
    execution: 'governed',
    label: 'Reset password',
    description: 'Force a password reset for an account in Okta, Entra or Google Workspace.',
    accent: '#fb923c',
    bgColor: '#3d2a1a',
    icon: '🔑',
    shortCode: 'pwd',
    fields: [
      USER_TARGET,
      {
        key: 'send_email',
        label: 'Email the user a reset link',
        kind: 'boolean',
        defaultValue: true,
        help: 'Okta only. Entra and Workspace have no equivalent option and ignore it.',
      },
    ],
  },
  revoke_session: {
    type: 'revoke_session',
    execution: 'governed',
    label: 'Revoke sessions',
    description:
      "Kill an account's live sessions and refresh tokens. Leaves the account enabled — use Disable user for that.",
    accent: '#f59e0b',
    bgColor: '#3d2a1a',
    icon: '🚪',
    shortCode: 'ses',
    fields: [USER_TARGET],
  },
  force_mfa: {
    type: 'force_mfa',
    execution: 'governed',
    label: 'Force MFA',
    description: 'Require the account to re-enrol its second factor at next sign-in.',
    accent: '#f59e0b',
    bgColor: '#3d2a1a',
    icon: '📲',
    shortCode: 'mfa',
    fields: [USER_TARGET],
  },
  kill_process: {
    type: 'kill_process',
    execution: 'governed',
    label: 'Kill process',
    description:
      'Terminate a process on an endpoint. A killed process cannot be un-killed, but the effect does not persist: a service restarts, a user runs the program again.',
    accent: '#f472b6',
    bgColor: '#3d1a2e',
    icon: '💀',
    shortCode: 'kill',
    fields: [
      HOST_TARGET,
      {
        key: 'pid',
        label: 'Process ID',
        kind: 'number',
        placeholder: '4821',
        help: 'CrowdStrike terminates by PID and refuses the action without one.',
      },
      {
        key: 'process_name',
        label: 'Process name',
        kind: 'string',
        placeholder: 'rundll32.exe',
        help: 'SentinelOne targets binaries by name rather than PID. Give at least one of the two.',
      },
    ],
  },
  quarantine_file: {
    type: 'quarantine_file',
    execution: 'governed',
    label: 'Quarantine file',
    description:
      'Move a file on an endpoint into vendor quarantine. Quarantining a legitimate binary breaks whatever depended on it.',
    accent: '#f472b6',
    bgColor: '#3d1a2e',
    icon: '🧪',
    shortCode: 'qrn',
    fields: [
      HOST_TARGET,
      {
        key: 'file_path',
        label: 'File path',
        kind: 'string',
        required: true,
        placeholder: 'C:\\Users\\Public\\svchost.exe',
        help: 'Absolute path on the host. Required: with no path the executor falls back to the hostname.',
      },
      {
        key: 'file_hash',
        label: 'File hash',
        kind: 'string',
        placeholder: 'e3b0c44298fc1c14…',
        help: 'Optional. Recorded with the action so the file can be identified after the fact.',
      },
    ],
  },
  run_av_scan: {
    type: 'run_av_scan',
    execution: 'governed',
    label: 'Run AV scan',
    description: 'Start an antivirus scan on an endpoint. Consumes CPU on one host and finishes; nothing to undo.',
    accent: '#fb7185',
    bgColor: '#3d1a2e',
    icon: '🧹',
    shortCode: 'av',
    fields: [
      HOST_TARGET,
      {
        key: 'scan_type',
        label: 'Scan type',
        kind: 'select',
        required: true,
        options: AV_SCAN_TYPES,
        defaultValue: 'Full',
        help: 'Microsoft Defender honours the distinction. SentinelOne runs a full scan either way.',
      },
    ],
  },
  run_script: {
    type: 'run_script',
    execution: 'governed',
    label: 'Run script',
    description:
      'Execute a script on an endpoint. The most dangerous verb the platform has: the contract marks it severe, manual-rollback-only, and requires a named human — there is nothing to probe afterwards because the platform cannot know what an arbitrary script was meant to do.',
    accent: '#e11d48',
    bgColor: '#40161f',
    icon: '⚙️',
    shortCode: 'scr',
    fields: [
      HOST_TARGET,
      {
        key: 'script_name',
        label: 'Pre-staged script',
        kind: 'string',
        placeholder: 'collect-persistence',
        help: 'Name of a script already staged in the EDR console. Preferred: the body is reviewed once, there.',
      },
      {
        key: 'script_args',
        label: 'Arguments',
        kind: 'string',
        placeholder: '-Scope AllUsers',
        help: 'Passed to the pre-staged script. Ignored when a raw body is supplied below.',
      },
      {
        key: 'script_content',
        label: 'Raw script body',
        kind: 'textarea',
        placeholder: 'Get-CimInstance Win32_StartupCommand | ConvertTo-Json',
        help: 'Sent verbatim and used in preference to the pre-staged name. Give at least one of the two.',
      },
    ],
  },
  search_siem: {
    type: 'search_siem',
    execution: 'governed',
    label: 'Search SIEM',
    description:
      'Run a query against the connected SIEM and bring the rows back into the run context. Read-only, so the contract clears it at any confidence.',
    accent: '#38bdf8',
    bgColor: '#12304a',
    icon: '🔭',
    shortCode: 'siem',
    fields: [
      {
        key: 'query',
        label: 'Query',
        kind: 'textarea',
        required: true,
        placeholder: 'index=proxy dest_ip=203.0.113.10 earliest=-24h',
        help: 'SPL for Splunk, ES|QL for Elastic. Also the step target, so the run record names what was asked.',
      },
      {
        key: 'max_results',
        label: 'Maximum rows',
        kind: 'number',
        defaultValue: 500,
        help: 'Rows to bring back into the run context.',
      },
    ],
  },
  create_notable_event: {
    type: 'create_notable_event',
    execution: 'governed',
    label: 'Create notable event',
    description:
      'Raise a notable event in Splunk ES. Writes a record into someone else\u2019s queue: noise, not damage.',
    accent: '#0ea5e9',
    bgColor: '#12304a',
    icon: '📣',
    shortCode: 'note',
    fields: [
      {
        key: 'title',
        label: 'Title',
        kind: 'string',
        required: true,
        placeholder: 'Credential access on web-prod-04',
        help: 'The step target. Splunk records it as "AiSOC Alert — <title>" unless overridden below.',
      },
      {
        key: 'severity',
        label: 'Severity',
        kind: 'select',
        required: true,
        options: SEVERITIES,
        defaultValue: 'high',
      },
      {
        key: 'description',
        label: 'Description',
        kind: 'textarea',
        placeholder: 'Four failed sudo attempts followed by a successful root shell.',
      },
      {
        key: 'event_title',
        label: 'Exact title (optional)',
        kind: 'string',
        placeholder: 'SOC-2291 credential access',
        help: 'Recorded verbatim, without the "AiSOC Alert — " prefix.',
      },
    ],
  },
};

/**
 * Every step type the engine accepts, in registry order.
 *
 * Derived rather than restated: a hand-written copy of this list in
 * `StepInspector` and another in `PlaybookEditor` were two of the five
 * vocabularies.
 */
export const ALL_STEP_TYPES: readonly StepType[] = Object.keys(
  STEP_SCHEMAS,
) as StepType[];

/**
 * The types the palette may offer.
 *
 * Filtered on `execution`, not on a name: a type the engine cannot run must
 * not be offered as a thing to add, and hard-coding `!== 'approval'` would
 * stop being true the next time a verb is declared ahead of its handler.
 * Existing steps of an unrunnable type still render — an imported playbook
 * has to be readable in order to be fixed.
 */
export const AUTHORABLE_STEP_TYPES: readonly StepType[] = ALL_STEP_TYPES.filter(
  (type) => STEP_SCHEMAS[type].execution !== 'unimplemented',
);

/**
 * Default `params` object for a freshly added step. Honours `defaultValue`
 * on each field descriptor so the inspector form is never blank for known
 * required keys.
 */
export function defaultParamsFor(type: StepType): Record<string, unknown> {
  const schema = STEP_SCHEMAS[type];
  const params: Record<string, unknown> = {};
  for (const field of schema.fields) {
    if (field.defaultValue !== undefined) {
      params[field.key] = field.defaultValue;
    }
  }
  return params;
}

/** A validation problem, carrying the field it belongs to when it has one. */
export interface StepParamError {
  /** Param key this belongs to, or undefined for a whole-step problem. */
  key?: string;
  message: string;
}

function isBlank(value: unknown): boolean {
  return value === undefined || value === null || value === '';
}

/**
 * Validation problems for `params` against the schema for `type`, each tied
 * to the field it came from so the form can associate it with the control
 * rather than dumping an unattached list at the bottom.
 *
 * An empty array means the step is valid.
 */
export function validateStepFields(
  type: StepType,
  params: Record<string, unknown>,
): StepParamError[] {
  const schema = STEP_SCHEMAS[type];
  const errors: StepParamError[] = [];

  if (schema.execution === 'unimplemented') {
    errors.push({
      message:
        `${schema.label} steps are not runnable: the engine fails the step and the run stops there. ` +
        `Remove this step.`,
    });
  }

  for (const field of schema.fields) {
    const value = params[field.key];
    if (field.required && isBlank(value)) {
      errors.push({ key: field.key, message: `${field.label} is required.` });
    }
    if (field.kind === 'number' && !isBlank(value) && typeof value !== 'number') {
      errors.push({ key: field.key, message: `${field.label} must be a number.` });
    }
    if (
      field.kind === 'boolean' &&
      value !== undefined &&
      typeof value !== 'boolean'
    ) {
      errors.push({ key: field.key, message: `${field.label} must be true/false.` });
    }
    if (field.kind === 'string_list' && value !== undefined && !Array.isArray(value)) {
      errors.push({ key: field.key, message: `${field.label} must be a list.` });
    }
  }

  // Cross-field checks: a required-one-of cannot be expressed on a single
  // descriptor, and each of these mirrors a refusal in the executor rather
  // than a house style.
  if (type === 'notify') {
    const channel = params.channel;
    if (channel === 'pagerduty' && !params.service_key_env) {
      errors.push({
        key: 'service_key_env',
        message: 'PagerDuty channel requires a service-key env var.',
      });
    }
    if (channel === 'webhook' && !params.webhook_env) {
      errors.push({
        key: 'webhook_env',
        message: 'Webhook channel requires a webhook env var.',
      });
    }
  }
  if (type === 'kill_process' && isBlank(params.pid) && isBlank(params.process_name)) {
    errors.push({
      key: 'pid',
      message:
        'Give a process ID or a process name — CrowdStrike kills by PID, SentinelOne by name, and neither can act on nothing.',
    });
  }
  if (
    type === 'run_script' &&
    isBlank(params.script_name) &&
    isBlank(params.script_content)
  ) {
    errors.push({
      key: 'script_name',
      message: 'Name a pre-staged script or supply a raw body; there is nothing to run otherwise.',
    });
  }

  return errors;
}

/**
 * Human-readable validation problems for the given params object.
 *
 * Kept as the string-shaped view over {@link validateStepFields} for callers
 * that only render a list.
 */
export function validateStepParams(
  type: StepType,
  params: Record<string, unknown>,
): string[] {
  return validateStepFields(type, params).map((error) => error.message);
}
