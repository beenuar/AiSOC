/**
 * WCAG 2.1 AA sweep over the step inspector — every step type it can render.
 *
 * These are forms, and they carry the two defects forms carry: a `<label>`
 * that sits beside its control rather than pointing at it, and an error
 * summary that names a field without being reachable from it. The inspector
 * had both. Thirteen new forms went in on top, so the sweep runs over the
 * whole vocabulary rather than one representative type — a schema whose
 * descriptor happens to produce an unlabelled control would otherwise be
 * caught only if somebody had picked that step type for the test.
 *
 * `color-contrast` is disabled for the same reason as
 * `src/test/a11y.test.tsx`: jsdom does not compute CSS variables, so the rule
 * returns "incomplete" rather than a useful answer.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { StepInspector } from './StepInspector';
import { ALL_STEP_TYPES, STEP_SCHEMAS, defaultParamsFor } from './stepSchemas';
import type { PlaybookStep, StepType } from './types';

const AXE_OPTIONS = { rules: { 'color-contrast': { enabled: false } } };

function stepOf(type: StepType): PlaybookStep {
  return {
    id: 'step-1',
    name: `A ${STEP_SCHEMAS[type].label} step`,
    type,
    params: defaultParamsFor(type),
    on_failure: 'abort',
    retry_max: 0,
    timeout_seconds: 30,
  };
}

afterEach(cleanup);

describe('StepInspector — WCAG 2.1 AA', () => {
  it.each(ALL_STEP_TYPES.map((type) => [type] as const))(
    'the %s form has no accessibility violations',
    async (type) => {
      const { container } = render(
        <StepInspector step={stepOf(type)} onUpdate={vi.fn()} onDelete={vi.fn()} />,
      );
      expect(await axe(container, AXE_OPTIONS)).toHaveNoViolations();
    },
  );

  it('associates every parameter control with its label, exactly one each', () => {
    for (const type of ALL_STEP_TYPES) {
      render(<StepInspector step={stepOf(type)} onUpdate={vi.fn()} onDelete={vi.fn()} />);
      for (const field of STEP_SCHEMAS[type].fields) {
        // Matched exactly rather than by substring: "Title" is a substring of
        // "Exact title (optional)", and a substring match that happens to hit
        // two controls would pass for a field whose label reaches neither.
        // Throws when no control carries the label, which is the state every
        // one of these was in before.
        const controls = screen.getAllByLabelText(
          (content) => stripRequiredMarker(content) === field.label,
        );
        expect(controls, `${type}.${field.key} has no uniquely-labelled control`).toHaveLength(1);
      }
      cleanup();
    }
  });

  it('reaches a field error from the control it belongs to', () => {
    // `quarantine_file` requires a path and the default params have none, so
    // the inspector renders with a real validation error rather than a
    // synthetic one.
    render(
      <StepInspector step={stepOf('quarantine_file')} onUpdate={vi.fn()} onDelete={vi.fn()} />,
    );
    expect(screen.getByLabelText(/File path/i)).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByLabelText(/File path/i)).toHaveAccessibleDescription(
      /File path is required/i,
    );
  });

  it('tells a screen reader that an unrunnable step will not run', async () => {
    const unrunnable = ALL_STEP_TYPES.filter(
      (t) => STEP_SCHEMAS[t].execution === 'unimplemented',
    );
    expect(unrunnable.length).toBeGreaterThan(0);
    for (const type of unrunnable) {
      const { container } = render(
        <StepInspector step={stepOf(type)} onUpdate={vi.fn()} onDelete={vi.fn()} />,
      );
      const note = screen.getByRole('note');
      expect(note).toHaveTextContent(/will not run this step/i);
      expect(await axe(container, AXE_OPTIONS)).toHaveNoViolations();
      cleanup();
    }
  });
});

/** The label text without the "(required)" marker the form appends to it. */
function stripRequiredMarker(content: string): string {
  return content.replace(/\s*\(required\)\s*$/, '').trim();
}
