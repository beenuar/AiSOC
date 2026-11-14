/**
 * connectionValidation
 * ====================
 *
 * Pure helpers that decide whether a proposed edge between two playbook
 * steps is structurally valid, and write user-drawn edges back into the
 * `PlaybookStep.next_true` / `next_false` fields the backend stores.
 *
 * The visual canvas previously let users freely drop arbitrary edges that
 * never persisted (silent data loss on save). This module makes the
 * editor honest:
 *
 *   1. Disallow self-loops.
 *   2. Disallow duplicate edges between the same source/target pair.
 *   3. Disallow edges that introduce a cycle (DAG invariant).
 *   4. Only `condition` steps support a true/false branch fork. Linear
 *      steps may have at most ONE outgoing edge (sequential next).
 *   5. `close_case` is a terminal step — it has no outgoing edge.
 *   6. Everything else is rejected with a structured reason that the UI
 *      can surface as a toast.
 */

import type { PlaybookStep, StepType } from './types';

export type EdgeBranch = 'true' | 'false' | 'next';

export interface ValidationFailure {
  ok: false;
  reason: string;
}

export interface ValidationSuccess {
  ok: true;
  branch: EdgeBranch;
}

export type ValidationResult = ValidationFailure | ValidationSuccess;

const TERMINAL_TYPES: ReadonlySet<StepType> = new Set<StepType>(['close_case']);

/**
 * Returns true iff there is already a path from `start` to `goal` via the
 * declared `next_true` / `next_false` edges (visiting each node once). This
 * is the basis of the cycle check: the proposed edge would create a cycle
 * iff the *target* already has a path back to the *source*.
 */
export function hasPath(
  steps: PlaybookStep[],
  start: string,
  goal: string,
): boolean {
  if (start === goal) return true;
  const byId = new Map(steps.map((s) => [s.id, s]));
  const stack: string[] = [start];
  const seen = new Set<string>();
  while (stack.length) {
    const id = stack.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const node = byId.get(id);
    if (!node) continue;
    if (node.next_true) {
      if (node.next_true === goal) return true;
      stack.push(node.next_true);
    }
    if (node.next_false) {
      if (node.next_false === goal) return true;
      stack.push(node.next_false);
    }
  }
  return false;
}

/**
 * Validates a proposed edge from `sourceId` to `targetId`.
 *
 * The optional `sourceHandle` is the React Flow handle id, which we use to
 * decide whether the edge should land on the true or false branch of a
 * `condition` step. For non-condition sources the value is ignored.
 */
export function validateConnection(
  steps: PlaybookStep[],
  sourceId: string,
  targetId: string,
  sourceHandle?: string | null,
): ValidationResult {
  if (sourceId === targetId) {
    return { ok: false, reason: 'A step cannot connect to itself.' };
  }
  const byId = new Map(steps.map((s) => [s.id, s]));
  const source = byId.get(sourceId);
  const target = byId.get(targetId);
  if (!source) {
    return { ok: false, reason: `Source step ${sourceId} no longer exists.` };
  }
  if (!target) {
    return { ok: false, reason: `Target step ${targetId} no longer exists.` };
  }
  if (TERMINAL_TYPES.has(source.type)) {
    return {
      ok: false,
      reason: `${source.type} is terminal — it cannot have outgoing edges.`,
    };
  }

  // Cycle check — would an edge source→target close a loop back to source?
  if (hasPath(steps, targetId, sourceId)) {
    return {
      ok: false,
      reason: 'That connection would create a cycle. Playbooks must be acyclic.',
    };
  }

  if (source.type === 'condition') {
    const branch: EdgeBranch =
      sourceHandle === 'false' ? 'false' : 'true';
    const slot = branch === 'true' ? source.next_true : source.next_false;
    if (slot === targetId) {
      return {
        ok: false,
        reason: `Condition already has a ${branch} branch to that step.`,
      };
    }
    return { ok: true, branch };
  }

  // Linear step: a single outbound edge stored in next_true.
  if (source.next_true && source.next_true !== targetId) {
    return {
      ok: false,
      reason:
        'This step already has an outgoing connection. Remove it before adding a new one, or convert to a condition.',
    };
  }
  if (source.next_true === targetId) {
    return {
      ok: false,
      reason: 'That connection already exists.',
    };
  }
  return { ok: true, branch: 'next' };
}

/**
 * Apply a validated connection to the steps array. Pure, returns a new
 * array. Caller is expected to have already invoked `validateConnection`
 * and confirmed `ok: true`.
 */
export function applyConnection(
  steps: PlaybookStep[],
  sourceId: string,
  targetId: string,
  branch: EdgeBranch,
): PlaybookStep[] {
  return steps.map((s) => {
    if (s.id !== sourceId) return s;
    if (branch === 'true') return { ...s, next_true: targetId };
    if (branch === 'false') return { ...s, next_false: targetId };
    return { ...s, next_true: targetId };
  });
}

/**
 * Remove an edge by clearing the matching next_true / next_false slot on
 * the source. Pure, returns a new array. If the source has neither slot
 * pointing at the target the steps array is returned unchanged.
 */
export function removeConnection(
  steps: PlaybookStep[],
  sourceId: string,
  targetId: string,
): PlaybookStep[] {
  return steps.map((s) => {
    if (s.id !== sourceId) return s;
    let changed = false;
    let nextTrue = s.next_true;
    let nextFalse = s.next_false;
    if (nextTrue === targetId) {
      nextTrue = undefined;
      changed = true;
    }
    if (nextFalse === targetId) {
      nextFalse = undefined;
      changed = true;
    }
    if (!changed) return s;
    return { ...s, next_true: nextTrue, next_false: nextFalse };
  });
}

/**
 * Strip every reference (incoming and outgoing) to `removedIds` from the
 * surviving steps. Used after bulk delete so dangling next_true/next_false
 * pointers don't render as broken edges on next layout.
 */
export function pruneReferences(
  steps: PlaybookStep[],
  removedIds: Iterable<string>,
): PlaybookStep[] {
  const drop = new Set(removedIds);
  return steps
    .filter((s) => !drop.has(s.id))
    .map((s) => {
      let nt = s.next_true;
      let nf = s.next_false;
      if (nt && drop.has(nt)) nt = undefined;
      if (nf && drop.has(nf)) nf = undefined;
      if (nt === s.next_true && nf === s.next_false) return s;
      return { ...s, next_true: nt, next_false: nf };
    });
}
