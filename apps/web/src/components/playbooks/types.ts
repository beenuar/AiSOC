/**
 * Shared TypeScript types for the Playbook editor and list UI.
 * Mirrors services/agents/app/playbook/models.py
 */

export type StepType =
  | 'enrich'
  | 'investigate'
  | 'notify'
  | 'block_ip'
  | 'isolate_host'
  | 'create_ticket'
  | 'close_case'
  | 'http'
  | 'condition';

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
