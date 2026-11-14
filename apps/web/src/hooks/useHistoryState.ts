'use client';

/**
 * useHistoryState
 * ===============
 *
 * Generic time-travel state hook. Wraps `useState` with an explicit history
 * stack so callers can undo / redo arbitrary mutations.
 *
 * Design notes (WS-F4 — Visual SOAR studio polish):
 *   - History is bounded to `historyLimit` entries (default 50) to keep
 *     memory bounded for long editing sessions on big playbooks.
 *   - Calling `set` collapses the future stack — i.e. once the user makes
 *     a new change after undoing, the redo branch is discarded. This is
 *     the same model browsers and most IDEs use.
 *   - `replace(next)` updates `present` *without* pushing to history. Useful
 *     for "syncing" with remote data on first load: we do not want the load
 *     to count as an undoable action.
 *   - Equality is by reference. Callers should already produce a fresh
 *     object when they intend a real change (which is standard React state
 *     practice anyway).
 *
 * Returned tuple shape mimics `[state, setState]` from `useState` so the
 * hook is a near drop-in replacement.
 */

import { useCallback, useRef, useState } from 'react';

export interface HistoryControls<T> {
  set: (next: T | ((prev: T) => T)) => void;
  replace: (next: T) => void;
  undo: () => boolean;
  redo: () => boolean;
  reset: (next: T) => void;
  canUndo: boolean;
  canRedo: boolean;
  pastSize: number;
  futureSize: number;
}

export interface HistoryStateOptions {
  /**
   * Maximum number of entries to keep on the past stack. When exceeded the
   * oldest entry is dropped. Defaults to 50.
   */
  historyLimit?: number;
}

export function useHistoryState<T>(
  initial: T | (() => T),
  options: HistoryStateOptions = {},
): [T, HistoryControls<T>] {
  const limit = options.historyLimit ?? 50;

  const [present, setPresent] = useState<T>(initial);
  // Stacks live in refs to keep referential stability for the controls
  // object across renders. We bump `version` to force re-render when stack
  // sizes change so `canUndo` / `canRedo` flip correctly.
  const past = useRef<T[]>([]);
  const future = useRef<T[]>([]);
  const [, bump] = useState(0);

  const forceRerender = useCallback(() => bump((v) => v + 1), []);

  const set = useCallback(
    (next: T | ((prev: T) => T)) => {
      setPresent((prev) => {
        const resolved =
          typeof next === 'function' ? (next as (p: T) => T)(prev) : next;
        if (Object.is(resolved, prev)) {
          return prev;
        }
        past.current = [...past.current, prev];
        if (past.current.length > limit) {
          past.current = past.current.slice(past.current.length - limit);
        }
        future.current = [];
        forceRerender();
        return resolved;
      });
    },
    [forceRerender, limit],
  );

  const replace = useCallback(
    (next: T) => {
      setPresent(next);
      // History stays intact; this is meant for non-undoable syncs.
    },
    [],
  );

  const undo = useCallback((): boolean => {
    if (past.current.length === 0) {
      return false;
    }
    const previous = past.current[past.current.length - 1];
    past.current = past.current.slice(0, past.current.length - 1);
    setPresent((curr) => {
      future.current = [curr, ...future.current];
      return previous;
    });
    forceRerender();
    return true;
  }, [forceRerender]);

  const redo = useCallback((): boolean => {
    if (future.current.length === 0) {
      return false;
    }
    const next = future.current[0];
    future.current = future.current.slice(1);
    setPresent((curr) => {
      past.current = [...past.current, curr];
      if (past.current.length > limit) {
        past.current = past.current.slice(past.current.length - limit);
      }
      return next;
    });
    forceRerender();
    return true;
  }, [forceRerender, limit]);

  const reset = useCallback(
    (next: T) => {
      past.current = [];
      future.current = [];
      setPresent(next);
      forceRerender();
    },
    [forceRerender],
  );

  const controls: HistoryControls<T> = {
    set,
    replace,
    undo,
    redo,
    reset,
    canUndo: past.current.length > 0,
    canRedo: future.current.length > 0,
    pastSize: past.current.length,
    futureSize: future.current.length,
  };

  return [present, controls];
}
