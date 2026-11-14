/**
 * connectionValidation — unit tests
 * =================================
 *
 * The visual canvas leans on these helpers to keep the playbook DAG
 * coherent. If any of these rules silently regress, the editor will
 * "lose" edges on save (a frustrating, hard-to-debug class of bug).
 *
 * Coverage map:
 *   - validateConnection: self-loop, missing nodes, terminal sources,
 *     cycles, condition true/false branches, duplicate edges, linear
 *     overflow.
 *   - applyConnection: writes into next_true / next_false correctly.
 *   - removeConnection: clears both branches if they match.
 *   - pruneReferences: drops nodes and dangling pointers.
 *   - hasPath: BFS-style reachability used by the cycle detector.
 */

import { describe, expect, it } from 'vitest';
import {
  applyConnection,
  hasPath,
  pruneReferences,
  removeConnection,
  validateConnection,
} from './connectionValidation';
import type { PlaybookStep, StepType } from './types';

function step(
  id: string,
  type: StepType = 'enrich',
  overrides: Partial<PlaybookStep> = {},
): PlaybookStep {
  return {
    id,
    name: id,
    type,
    params: {},
    on_failure: 'abort',
    retry_max: 0,
    timeout_seconds: 30,
    ...overrides,
  };
}

describe('validateConnection', () => {
  it('rejects self-loops', () => {
    const steps = [step('a')];
    const r = validateConnection(steps, 'a', 'a');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/itself/i);
  });

  it('rejects when source step is missing', () => {
    const steps = [step('a')];
    const r = validateConnection(steps, 'ghost', 'a');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/Source.*ghost/);
  });

  it('rejects when target step is missing', () => {
    const steps = [step('a')];
    const r = validateConnection(steps, 'a', 'ghost');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/Target.*ghost/);
  });

  it('rejects outgoing edges from a terminal step (close_case)', () => {
    const steps = [step('a', 'close_case'), step('b')];
    const r = validateConnection(steps, 'a', 'b');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/terminal/i);
  });

  it('rejects edges that would create a cycle', () => {
    // a -> b -> c, then proposing c -> a would close the loop.
    const steps = [
      step('a', 'enrich', { next_true: 'b' }),
      step('b', 'enrich', { next_true: 'c' }),
      step('c'),
    ];
    const r = validateConnection(steps, 'c', 'a');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/cycle/i);
  });

  it('accepts a fresh linear edge and labels it "next"', () => {
    const steps = [step('a'), step('b')];
    const r = validateConnection(steps, 'a', 'b');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.branch).toBe('next');
  });

  it('rejects a second outgoing edge from a non-condition source', () => {
    const steps = [
      step('a', 'enrich', { next_true: 'b' }),
      step('b'),
      step('c'),
    ];
    const r = validateConnection(steps, 'a', 'c');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/already has an outgoing/i);
  });

  it('rejects an exact-duplicate linear edge', () => {
    const steps = [step('a', 'enrich', { next_true: 'b' }), step('b')];
    const r = validateConnection(steps, 'a', 'b');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/already exists/i);
  });

  it('routes a condition source to the true branch by default', () => {
    const steps = [step('a', 'condition'), step('b')];
    const r = validateConnection(steps, 'a', 'b');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.branch).toBe('true');
  });

  it('routes a condition source to the false branch when handle is "false"', () => {
    const steps = [step('a', 'condition'), step('b')];
    const r = validateConnection(steps, 'a', 'b', 'false');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.branch).toBe('false');
  });

  it('lets a condition fan out to true AND false to different targets', () => {
    // condition already wired to true=b; we now ask to wire false=c.
    const steps = [
      step('a', 'condition', { next_true: 'b' }),
      step('b'),
      step('c'),
    ];
    const r = validateConnection(steps, 'a', 'c', 'false');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.branch).toBe('false');
  });

  it('rejects re-wiring the same branch on a condition to the same target', () => {
    const steps = [
      step('a', 'condition', { next_true: 'b' }),
      step('b'),
    ];
    const r = validateConnection(steps, 'a', 'b', 'true');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/true branch/i);
  });
});

describe('applyConnection', () => {
  it('writes into next_true on a "next" branch', () => {
    const steps = [step('a'), step('b')];
    const out = applyConnection(steps, 'a', 'b', 'next');
    expect(out[0].next_true).toBe('b');
    expect(out[0].next_false).toBeUndefined();
  });

  it('writes into next_true on a "true" branch', () => {
    const steps = [step('a', 'condition'), step('b')];
    const out = applyConnection(steps, 'a', 'b', 'true');
    expect(out[0].next_true).toBe('b');
  });

  it('writes into next_false on a "false" branch', () => {
    const steps = [step('a', 'condition'), step('b')];
    const out = applyConnection(steps, 'a', 'b', 'false');
    expect(out[0].next_false).toBe('b');
    expect(out[0].next_true).toBeUndefined();
  });

  it('returns a new array — pure / immutable', () => {
    const steps = [step('a'), step('b')];
    const out = applyConnection(steps, 'a', 'b', 'next');
    expect(out).not.toBe(steps);
    expect(out[0]).not.toBe(steps[0]);
    expect(steps[0].next_true).toBeUndefined();
  });
});

describe('removeConnection', () => {
  it('clears next_true when it matches', () => {
    const steps = [step('a', 'enrich', { next_true: 'b' }), step('b')];
    const out = removeConnection(steps, 'a', 'b');
    expect(out[0].next_true).toBeUndefined();
  });

  it('clears next_false when it matches', () => {
    const steps = [
      step('a', 'condition', { next_false: 'b' }),
      step('b'),
    ];
    const out = removeConnection(steps, 'a', 'b');
    expect(out[0].next_false).toBeUndefined();
  });

  it('returns the source object unchanged when no slot matches', () => {
    const steps = [step('a', 'enrich', { next_true: 'c' }), step('b'), step('c')];
    const out = removeConnection(steps, 'a', 'b');
    // Same reference for the unaffected source step (no churn for memoized renderers).
    expect(out[0]).toBe(steps[0]);
  });
});

describe('pruneReferences', () => {
  it('drops removed nodes and clears dangling pointers', () => {
    // a -> b (will delete) -> c, plus a condition d with false=b.
    const steps = [
      step('a', 'enrich', { next_true: 'b' }),
      step('b', 'enrich', { next_true: 'c' }),
      step('c'),
      step('d', 'condition', { next_true: 'c', next_false: 'b' }),
    ];
    const out = pruneReferences(steps, ['b']);
    const ids = out.map((s) => s.id).sort();
    expect(ids).toEqual(['a', 'c', 'd']);

    const a = out.find((s) => s.id === 'a')!;
    const d = out.find((s) => s.id === 'd')!;
    expect(a.next_true).toBeUndefined();
    expect(d.next_false).toBeUndefined();
    // Untouched pointer is still intact.
    expect(d.next_true).toBe('c');
  });

  it('returns the same step ref when no pointers changed', () => {
    const steps = [step('a', 'enrich', { next_true: 'b' }), step('b')];
    const out = pruneReferences(steps, ['c']);
    expect(out[0]).toBe(steps[0]);
    expect(out[1]).toBe(steps[1]);
  });
});

describe('hasPath', () => {
  it('returns true for the trivial start === goal case', () => {
    expect(hasPath([step('a')], 'a', 'a')).toBe(true);
  });

  it('walks both true and false branches', () => {
    const steps = [
      step('a', 'condition', { next_true: 'b', next_false: 'c' }),
      step('b'),
      step('c', 'enrich', { next_true: 'd' }),
      step('d'),
    ];
    expect(hasPath(steps, 'a', 'd')).toBe(true);
    expect(hasPath(steps, 'a', 'b')).toBe(true);
  });

  it('returns false for unreachable goals', () => {
    const steps = [step('a', 'enrich', { next_true: 'b' }), step('b'), step('c')];
    expect(hasPath(steps, 'a', 'c')).toBe(false);
  });

  it('does not loop forever on a malformed cyclic graph', () => {
    // The validator prevents these from being created via the UI but the
    // function itself should still terminate on bad input that arrived
    // via a JSON paste or a buggy backend.
    const steps = [
      step('a', 'enrich', { next_true: 'b' }),
      step('b', 'enrich', { next_true: 'a' }),
    ];
    expect(hasPath(steps, 'a', 'c')).toBe(false);
  });
});
