/**
 * Playbook / SOAR automation types.
 *
 * These mirror `schemas/playbook.schema.json` and the runtime model in
 * `services/agents/app/playbook/models.py`, and
 * `scripts/check_playbook_schema_parity.py` fails the build when they drift.
 *
 * They used to describe a different product. The previous version declared a
 * 28-member `ActionType` union (`notify_email`, `create_ticket_jira`,
 * `collect_forensics`, `run_query_splunk`, …) that matched neither the schema
 * nor the engine, a `PlaybookStep.action: ActionConfig` shape the engine does
 * not parse, `depends_on` / `run_parallel` / `blast_radius_check` fields
 * nothing reads, and `waiting_approval` / `paused` run states the engine
 * cannot enter — it is a single-threaded index walk with no pause or resume.
 * Nothing imported it, so the drift was invisible; a shared-types package
 * that is wrong is worse than one that is absent, because the next person to
 * import it inherits a contract the server will reject.
 */

/** What can start a playbook. Mirrors `trigger.on` in the schema. */
export type PlaybookTrigger = "alert" | "case" | "manual" | "schedule";

/**
 * Every step type the engine accepts. Mirrors `StepType`.
 *
 * What the engine *does* with each one is published in the schema's
 * `x-aisoc-execution` map and reflected in {@link StepExecution} below —
 * accepting a step type and performing it are different claims, and the
 * distinction is the point.
 */
export type StepType =
  | "enrich"
  | "investigate"
  | "notify"
  | "block_ip"
  | "block_ioc"
  | "isolate_host"
  | "create_ticket"
  | "close_case"
  | "http"
  | "condition"
  | "osquery_live_query"
  | "approval"
  | "disable_user"
  | "reset_password"
  | "revoke_session"
  | "force_mfa"
  | "kill_process"
  | "quarantine_file"
  | "run_av_scan"
  | "run_script"
  | "search_siem"
  | "create_notable_event";

/**
 * What happens when a step of a given type runs.
 *
 * - `executed` — a handler runs and has a real effect.
 * - `governed` — the step is dispatched to the action registry in
 *   `services/actions`, where the capability contract and the tenant's
 *   autonomy policy decide whether a vendor is touched. Whether one *was* is
 *   answered per run by {@link StepDispatchReport.executed}, never assumed.
 * - `unimplemented` — no handler; the engine fails the step closed rather
 *   than reporting a success it did not achieve.
 */
export type StepExecution = "executed" | "governed" | "unimplemented";

/**
 * Guard on a step. Either the structured form or an expression string.
 *
 * The expression parser is deliberately restricted to one comparison: no
 * `and`/`or` chains, no function calls, no `eval`.
 */
export interface StepCondition {
  field?: string;
  operator?: "eq" | "ne" | "gt" | "lt" | "contains" | "exists";
  value?: unknown;
  expression?: string;
}

export interface PlaybookStep {
  id: string;
  name: string;
  type: StepType;
  /** Free-form per-verb arguments. Each executor declares its own shape. */
  params?: Record<string, unknown>;
  condition?: StepCondition | string;
  on_failure?: "abort" | "continue" | "retry";
  /** Ceiling is 25 (`bounds.ABSOLUTE_MAX_RETRIES`). */
  retry_max?: number;
  /** 1..3600 seconds (`bounds.ABSOLUTE_MAX_TIMEOUT_SECONDS`). */
  timeout_seconds?: number;
  /** Step id to jump to. The engine branches; it does not build a DAG. */
  next_true?: string;
  next_false?: string;
}

export interface Playbook {
  id?: string;
  name: string;
  description?: string;
  version?: string;
  tags?: string[];
  trigger?: {
    on?: PlaybookTrigger;
    [key: string]: unknown;
  };
  steps: PlaybookStep[];
  author?: string;
  enabled?: boolean;
  created_at?: string;
  updated_at?: string;
  /**
   * Authored documentation the engine does not read. Declared because real
   * playbooks carry them and a schema that rejected them would be wrong;
   * named here so nobody mistakes them for behaviour.
   */
  inputs?: Record<string, unknown>;
  dry_run_support?: boolean;
}

/** Mirrors `RunStatus`. There is no `paused` and no `waiting_approval`. */
export type PlaybookRunStatus = "pending" | "running" | "completed" | "failed" | "cancelled";

/** Mirrors `StepStatus`. */
export type PlaybookStepStatus = "pending" | "skipped" | "running" | "success" | "failed";

/**
 * What a governed response step reports back.
 *
 * `executed` is the single field that means a vendor was actually touched. A
 * preview, an approval queue, a blocked action and a tenant with no
 * integration are all `false`, and `status` says which.
 */
export interface StepDispatchReport {
  capability: string;
  status:
    | "executed"
    | "awaiting_completion"
    | "dry_run"
    | "simulated"
    | "pending_approval"
    | "blocked"
    | "no_integration"
    | "unsupported"
    | "failed";
  executed: boolean;
  summary: string;
  vendor_id?: string;
  detail?: string;
  /** Absent when the action did not run: there is nothing to read back. */
  verification?: "verified" | "failed" | "unverified";
  verification_reason?: string;
  autonomy_mode?: string;
  blast_radius?: string;
}

export interface PlaybookStepResult {
  step_id: string;
  name: string;
  status: PlaybookStepStatus;
  /** The handler's return value. For a governed step, a {@link StepDispatchReport}. */
  result?: Record<string, unknown>;
  /** Set on a `condition` step: the step id the engine jumped to. */
  branch?: string;
}

export interface PlaybookRun {
  run_id: string;
  playbook_id: string;
  playbook_name: string;
  status: PlaybookRunStatus;
  /** Trigger context plus every step's flattened output. */
  context: Record<string, unknown>;
  step_results: PlaybookStepResult[];
  started_at: string;
  finished_at: string;
  error?: string | null;
}
