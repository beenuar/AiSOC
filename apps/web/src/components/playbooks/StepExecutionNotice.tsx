'use client';

/**
 * What the engine will actually do with a step of this type.
 *
 * The three states come from the schema's `x-aisoc-execution` map, which
 * `scripts/check_playbook_schema_parity.py` compares against the engine's
 * real handler table in both directions — so this is a checked fact rather
 * than a label somebody typed.
 *
 * The distinction the editor has to keep is between *accepting* a step type
 * and *performing* it:
 *
 *  - `executed` — a handler runs in the agents service.
 *  - `governed` — the step is handed to the action registry, which grades it
 *    against the capability contract and the tenant's autonomy policy. That
 *    is not the same as a vendor being touched, and the run's own report says
 *    which happened. Saying "this will isolate the host" would be a promise
 *    the editor is in no position to make.
 *  - `unimplemented` — there is no handler. The engine fails the step closed
 *    and the default `on_failure: abort` halts the run. `approval` is the one
 *    type in this state and it is deliberate: an approval step is a pause and
 *    the engine has nothing to suspend.
 *
 * Colour never carries the meaning on its own — each state is named in text,
 * because the WCAG AA gate is not the only reason that matters.
 */

import React from 'react';
import type { StepSchema } from './stepSchemas';

const BADGE: Record<StepSchema['execution'], { text: string; className: string }> = {
  executed: {
    text: 'Runs in the engine',
    className: 'text-sky-300 border-sky-800 bg-sky-950/40',
  },
  governed: {
    text: 'Governed action',
    className: 'text-amber-300 border-amber-800 bg-amber-950/40',
  },
  unimplemented: {
    text: 'Not runnable',
    className: 'text-red-300 border-red-800 bg-red-950/40',
  },
};

const EXPLANATION: Record<StepSchema['execution'], string> = {
  executed: 'The agents service handles this step directly.',
  governed:
    'Dispatched to the action registry, which applies this capability\u2019s contract and the ' +
    'tenant\u2019s autonomy policy. Reaching dispatch is not the same as a vendor being changed: ' +
    'a preview, an approval queue and a missing integration are each reported as not executed.',
  unimplemented: '',
};

export function StepExecutionNotice({ schema }: { schema: StepSchema }) {
  const badge = BADGE[schema.execution];
  const unavailable = schema.unavailable;

  return (
    <div className="space-y-2">
      <p className="flex items-center gap-2 text-xs text-gray-500 leading-relaxed">
        <span
          className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${badge.className}`}
        >
          {badge.text}
        </span>
        <span>{schema.description}</span>
      </p>

      {EXPLANATION[schema.execution] && (
        <p className="text-[11px] text-gray-500 leading-relaxed">
          {EXPLANATION[schema.execution]}
        </p>
      )}

      {unavailable && (
        // `role="note"` rather than `alert`: this is a standing property of
        // the step type, not something that just went wrong, and an assertive
        // live region firing on every selection would be noise.
        <div
          role="note"
          aria-label={`${schema.label} steps cannot run`}
          className="rounded border border-red-900 bg-red-950/30 p-2 text-[11px] leading-relaxed text-red-200"
        >
          <p className="font-semibold">
            The engine will not run this step. It fails closed and the run stops
            there.
          </p>
          <p className="mt-1 text-red-300/90">{unavailable}</p>
        </div>
      )}
    </div>
  );
}
