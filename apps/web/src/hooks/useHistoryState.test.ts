/**
 * useHistoryState — unit tests
 * ============================
 *
 * Locks in the time-travel semantics the playbook editor relies on for
 * WS-F4 (Visual SOAR studio polish). Every behaviour exercised here maps
 * to a real editor flow:
 *
 *   - set / undo / redo round-trip   → keyboard shortcut handler
 *   - `set` clears the redo branch    → "edit after undo" rule
 *   - `replace` skips history         → remote SWR sync on first load
 *   - `reset` wipes everything         → post-save baseline
 *   - bounded history                  → long sessions don't leak memory
 *   - functional updaters              → setState((p) => …) form
 *   - no-op set is a no-op             → Object.is short-circuit
 */

import { describe, expect, it } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useHistoryState } from './useHistoryState';

describe('useHistoryState', () => {
  it('starts with the initial value and no history', () => {
    const { result } = renderHook(() => useHistoryState({ count: 0 }));
    const [state, controls] = result.current;
    expect(state).toEqual({ count: 0 });
    expect(controls.canUndo).toBe(false);
    expect(controls.canRedo).toBe(false);
    expect(controls.pastSize).toBe(0);
    expect(controls.futureSize).toBe(0);
  });

  it('pushes prior values onto the past stack on set()', () => {
    const { result } = renderHook(() => useHistoryState(0));

    act(() => {
      result.current[1].set(1);
    });
    expect(result.current[0]).toBe(1);
    expect(result.current[1].canUndo).toBe(true);
    expect(result.current[1].pastSize).toBe(1);

    act(() => {
      result.current[1].set(2);
    });
    expect(result.current[0]).toBe(2);
    expect(result.current[1].pastSize).toBe(2);
  });

  it('undo pops past back to present and pushes the old present onto future', () => {
    const { result } = renderHook(() => useHistoryState('a'));

    act(() => result.current[1].set('b'));
    act(() => result.current[1].set('c'));
    expect(result.current[0]).toBe('c');

    act(() => {
      const ok = result.current[1].undo();
      expect(ok).toBe(true);
    });
    expect(result.current[0]).toBe('b');
    expect(result.current[1].canRedo).toBe(true);

    act(() => {
      const ok = result.current[1].undo();
      expect(ok).toBe(true);
    });
    expect(result.current[0]).toBe('a');
    expect(result.current[1].canUndo).toBe(false);

    // undo past the bottom is a no-op and reports false.
    act(() => {
      const ok = result.current[1].undo();
      expect(ok).toBe(false);
    });
    expect(result.current[0]).toBe('a');
  });

  it('redo replays an undone change', () => {
    const { result } = renderHook(() => useHistoryState('a'));

    act(() => result.current[1].set('b'));
    act(() => result.current[1].undo());
    expect(result.current[0]).toBe('a');
    expect(result.current[1].canRedo).toBe(true);

    act(() => {
      const ok = result.current[1].redo();
      expect(ok).toBe(true);
    });
    expect(result.current[0]).toBe('b');
    expect(result.current[1].canRedo).toBe(false);

    // No redo to do; reports false.
    act(() => {
      const ok = result.current[1].redo();
      expect(ok).toBe(false);
    });
  });

  it('a fresh set() after undo discards the redo branch', () => {
    const { result } = renderHook(() => useHistoryState('a'));

    act(() => result.current[1].set('b'));
    act(() => result.current[1].set('c'));
    act(() => result.current[1].undo()); // back to 'b'
    expect(result.current[1].canRedo).toBe(true);

    act(() => result.current[1].set('d'));
    expect(result.current[0]).toBe('d');
    // Redo branch ('c') should be gone now — this is the core "edit after
    // undo" rule. Without it the user would see ghost history entries.
    expect(result.current[1].canRedo).toBe(false);
    expect(result.current[1].futureSize).toBe(0);
  });

  it('replace() updates state without touching history', () => {
    const { result } = renderHook(() => useHistoryState({ v: 0 }));

    act(() => result.current[1].set({ v: 1 }));
    act(() => result.current[1].set({ v: 2 }));
    const beforePast = result.current[1].pastSize;

    act(() => result.current[1].replace({ v: 99 }));
    expect(result.current[0]).toEqual({ v: 99 });
    // History stayed intact because replace() is the "remote sync" path.
    expect(result.current[1].pastSize).toBe(beforePast);
    expect(result.current[1].futureSize).toBe(0);
  });

  it('reset() clears past and future', () => {
    const { result } = renderHook(() => useHistoryState('a'));

    act(() => result.current[1].set('b'));
    act(() => result.current[1].set('c'));
    act(() => result.current[1].undo());
    expect(result.current[1].canUndo).toBe(true);
    expect(result.current[1].canRedo).toBe(true);

    act(() => result.current[1].reset('z'));
    expect(result.current[0]).toBe('z');
    expect(result.current[1].canUndo).toBe(false);
    expect(result.current[1].canRedo).toBe(false);
    expect(result.current[1].pastSize).toBe(0);
    expect(result.current[1].futureSize).toBe(0);
  });

  it('respects historyLimit and drops the oldest entry', () => {
    const { result } = renderHook(() =>
      useHistoryState(0, { historyLimit: 3 }),
    );

    // 5 sets → past stack should clamp at 3.
    act(() => result.current[1].set(1));
    act(() => result.current[1].set(2));
    act(() => result.current[1].set(3));
    act(() => result.current[1].set(4));
    act(() => result.current[1].set(5));

    expect(result.current[0]).toBe(5);
    expect(result.current[1].pastSize).toBe(3);

    // Three undos take us back as far as the bounded stack allows.
    act(() => result.current[1].undo()); // 4
    act(() => result.current[1].undo()); // 3
    act(() => result.current[1].undo()); // 2 (oldest preserved entry)
    expect(result.current[0]).toBe(2);
    expect(result.current[1].canUndo).toBe(false);
  });

  it('supports functional updaters in set()', () => {
    const { result } = renderHook(() => useHistoryState({ count: 0 }));

    act(() => {
      result.current[1].set((prev) => ({ count: prev.count + 1 }));
    });
    expect(result.current[0]).toEqual({ count: 1 });

    act(() => {
      result.current[1].set((prev) => ({ count: prev.count + 5 }));
    });
    expect(result.current[0]).toEqual({ count: 6 });
    expect(result.current[1].pastSize).toBe(2);
  });

  it('skips the history push when set() returns the identical value', () => {
    const obj = { v: 1 };
    const { result } = renderHook(() => useHistoryState(obj));

    act(() => {
      // Same reference → Object.is short-circuit, no history bump.
      result.current[1].set(obj);
    });
    expect(result.current[1].pastSize).toBe(0);
    expect(result.current[1].canUndo).toBe(false);
  });
});
