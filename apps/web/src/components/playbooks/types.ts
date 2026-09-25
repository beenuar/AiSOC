/**
 * Shared TypeScript types for the Playbook editor and list UI.
 *
 * `StepType` is re-exported from `@aisoc/types` rather than restated here.
 * The restatement was a nine-member union under a header comment claiming it
 * mirrored `services/agents/app/playbook/models.py`, which declares
 * twenty-two. Nothing checked the claim, and because `STEP_SCHEMAS` is keyed
 * `Record<StepType, StepSchema>` on the *local* union, thirteen missing forms
 * satisfied exhaustiveness and the build stayed green. Importing the published
 * union puts the compiler back in charge: a verb the engine grows is a type
 * error here until the editor can author it.
 *
 * `scripts/check_playbook_schema_parity.py` reads every declaration of this
 * vocabulary — the engine, the schema, the published package and this
 * directory — in both directions, so the comment above is a checked property
 * rather than an assertion.
 */

import type { StepType } from '@aisoc/types';

export type { StepType, StepExecution } from '@aisoc/types';

export type OnFailure = 'abort' | 'continue' | 'retry';

export interface StepCondition {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'lt' | 'contains' | 'exists';
  value?: unknown;
}

export interface PlaybookStep {
  id: string;
  name: string;
  type: StepType;
  params: Record<string, unknown>;
  condition?: StepCondition;
  on_failure: OnFailure;
  retry_max: number;
  timeout_seconds: number;
  next_true?: string;
  next_false?: string;
}

export interface PlaybookTrigger {
  on: 'alert' | 'case' | 'manual' | 'schedule';
  severity?: string[];
  tags?: string[];
  cron?: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  version: string;
  tags: string[];
  trigger: PlaybookTrigger;
  steps: PlaybookStep[];
  author: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export type PlaybookRunStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface PlaybookRunStep {
  step_id: string;
  step_name: string;
  status: 'pending' | 'running' | 'completed' | 'skipped' | 'failed';
  started_at?: string;
  completed_at?: string;
  output?: unknown;
  error?: string;
}

export interface PlaybookRun {
  run_id: string;
  playbook_id: string;
  playbook_name: string;
  status: PlaybookRunStatus;
  started_at?: string;
  completed_at?: string;
  steps: PlaybookRunStep[];
  context: Record<string, unknown>;
  dry_run: boolean;
}
