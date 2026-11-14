import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { act, renderHook } from "@testing-library/react";
import {
  FIXED_BASE_MS,
  MAX_DELAY_MS,
  MIN_DELAY_MS,
  useReplayController,
} from "./useReplayController";
import type { LedgerEvent } from "@/lib/api";

/**
 * These tests pin the playback contract for WS-D3. The visible behaviour
 * during a customer demo is "press ▶, watch each step light up at a
 * predictable cadence" — so the suite focuses on cadence, ordering, and
 * the auto-pause / auto-snap edge cases that would otherwise silently
 * stall the timeline.
 */

const makeEvent = (seq: number, durationMs = 1000): LedgerEvent => ({
  id: `evt-${seq}`,
  run_id: "run-1",
  seq,
  ts: new Date(2026, 0, 1, 0, 0, seq).toISOString(),
  kind: "tool_call",
  agent: "investigator",
  summary: `step ${seq}`,
  payload: null,
  input_hash: null,
  output_hash: null,
  duration_ms: durationMs,
});

const FIVE = [makeEvent(1), makeEvent(2), makeEvent(3), makeEvent(4), makeEvent(5)];

describe("useReplayController", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function setup(opts: {
    events?: readonly LedgerEvent[];
    initialSeq?: number | null;
    enabled?: boolean;
  } = {}) {
    const events = opts.events ?? FIVE;
    const setSelectedSeq = vi.fn<(seq: number) => void>();
    let selectedSeq: number | null = opts.initialSeq ?? null;
    setSelectedSeq.mockImplementation((s) => {
      selectedSeq = s;
    });

    const view = renderHook(
      ({ s }: { s: number | null }) =>
        useReplayController({
          events,
          selectedSeq: s,
          setSelectedSeq,
          enabled: opts.enabled ?? true,
        }),
      { initialProps: { s: selectedSeq } },
    );

    const sync = () => view.rerender({ s: selectedSeq });
    return {
      view,
      setSelectedSeq,
      events,
      get selectedSeq() {
        return selectedSeq;
      },
      sync,
    };
  }

  it("starts paused with no cursor when nothing is selected", () => {
    const { view } = setup({ initialSeq: null });
    expect(view.result.current.isPlaying).toBe(false);
    expect(view.result.current.currentIndex).toBeNull();
    expect(view.result.current.progress).toBe(0);
    expect(view.result.current.total).toBe(5);
  });

  it("play() snaps to first event when cursor is null and starts playback", () => {
    const ctx = setup({ initialSeq: null });
    act(() => ctx.view.result.current.play());
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(1);
    expect(ctx.view.result.current.isPlaying).toBe(true);
  });

  it("advances at FIXED_BASE_MS / speed in fixed mode", () => {
    const ctx = setup({ initialSeq: 1 });
    act(() => ctx.view.result.current.play());
    ctx.sync();

    // 1× → 1s per step.
    act(() => {
      vi.advanceTimersByTime(FIXED_BASE_MS - 1);
    });
    expect(ctx.setSelectedSeq).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(2);

    // Cursor moves → next tick scheduled.
    ctx.sync();
    act(() => {
      vi.advanceTimersByTime(FIXED_BASE_MS);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(3);
  });

  it("respects 4× speed in fixed mode", () => {
    const ctx = setup({ initialSeq: 1 });
    act(() => ctx.view.result.current.setSpeed(4));
    act(() => ctx.view.result.current.play());
    ctx.sync();

    act(() => {
      vi.advanceTimersByTime(FIXED_BASE_MS / 4);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(2);
  });

  it("uses each event's duration_ms in realtime mode (clamped to MIN/MAX)", () => {
    const events = [
      makeEvent(1, 200), // below MIN if MIN > 200? MIN is 50, so 200 is fine.
      makeEvent(2, 60_000), // above MAX, must be clamped.
      makeEvent(3, 1500),
    ];
    const ctx = setup({ events, initialSeq: 1 });
    act(() => ctx.view.result.current.setMode("realtime"));
    act(() => ctx.view.result.current.play());
    ctx.sync();

    // Step 1 → 2 should fire at 200ms (since 200 ∈ [MIN, MAX]).
    act(() => {
      vi.advanceTimersByTime(199);
    });
    expect(ctx.setSelectedSeq).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(2);

    // Step 2 → 3 should fire after MAX_DELAY_MS, not 60s.
    ctx.sync();
    act(() => {
      vi.advanceTimersByTime(MAX_DELAY_MS - 1);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(2);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(3);
  });

  it("auto-pauses on the last event (no looping)", () => {
    // Start at seq 1 — play() at the last event would re-snap to seq 1, but
    // testing the auto-pause separately keeps the harness simpler.
    const ctx = setup({ initialSeq: 1 });
    act(() => ctx.view.result.current.play());
    ctx.sync();

    // Fast-forward to the end (4 ticks for 5 events starting at index 0).
    for (let i = 0; i < 4; i++) {
      act(() => {
        vi.advanceTimersByTime(FIXED_BASE_MS);
      });
      ctx.sync();
    }
    expect(ctx.selectedSeq).toBe(5);
    // One more tick must not fire any more updates and should auto-pause.
    const callsAtEnd = ctx.setSelectedSeq.mock.calls.length;
    act(() => {
      vi.advanceTimersByTime(FIXED_BASE_MS * 2);
    });
    expect(ctx.setSelectedSeq.mock.calls.length).toBe(callsAtEnd);
    expect(ctx.view.result.current.isPlaying).toBe(false);
  });

  it("play() at the last event rewinds to the first event", () => {
    // Familiar media-player UX: pressing ▶ when parked at the end rewinds.
    const ctx = setup({ initialSeq: 5 });
    act(() => ctx.view.result.current.play());
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(1);
    expect(ctx.view.result.current.isPlaying).toBe(true);
  });

  it("pause() halts playback without changing the cursor", () => {
    const ctx = setup({ initialSeq: 1 });
    act(() => ctx.view.result.current.play());
    ctx.sync();
    act(() => {
      vi.advanceTimersByTime(FIXED_BASE_MS);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(2);
    ctx.sync();
    act(() => ctx.view.result.current.pause());
    expect(ctx.view.result.current.isPlaying).toBe(false);
    const callsAtPause = ctx.setSelectedSeq.mock.calls.length;
    act(() => {
      vi.advanceTimersByTime(FIXED_BASE_MS * 5);
    });
    expect(ctx.setSelectedSeq.mock.calls.length).toBe(callsAtPause);
  });

  it("stop() pauses and rewinds to the first event", () => {
    const ctx = setup({ initialSeq: 4 });
    act(() => ctx.view.result.current.stop());
    expect(ctx.view.result.current.isPlaying).toBe(false);
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(1);
  });

  it("stepForward / stepBackward clamp at the bounds", () => {
    const ctx = setup({ initialSeq: 5 });
    act(() => ctx.view.result.current.stepForward());
    // Already at last → no-op (still calls with 5).
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(5);

    act(() => ctx.view.result.current.stepBackward());
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(4);
  });

  it("seekToIndex clamps to [0, total - 1]", () => {
    const ctx = setup({ initialSeq: 1 });
    act(() => ctx.view.result.current.seekToIndex(99));
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(5);
    act(() => ctx.view.result.current.seekToIndex(-3));
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(1);
  });

  it("toggle() flips between playing and paused", () => {
    const ctx = setup({ initialSeq: 1 });
    expect(ctx.view.result.current.isPlaying).toBe(false);
    act(() => ctx.view.result.current.toggle());
    expect(ctx.view.result.current.isPlaying).toBe(true);
    act(() => ctx.view.result.current.toggle());
    expect(ctx.view.result.current.isPlaying).toBe(false);
  });

  it("disabling replay pauses without resetting the cursor", () => {
    const setSelectedSeq = vi.fn<(seq: number) => void>();
    let selectedSeq: number | null = 3;
    setSelectedSeq.mockImplementation((s) => {
      selectedSeq = s;
    });
    const view = renderHook(
      ({ enabled, s }: { enabled: boolean; s: number | null }) =>
        useReplayController({
          events: FIVE,
          selectedSeq: s,
          setSelectedSeq,
          enabled,
        }),
      { initialProps: { enabled: true, s: selectedSeq } },
    );
    act(() => view.result.current.play());
    expect(view.result.current.isPlaying).toBe(true);
    view.rerender({ enabled: false, s: selectedSeq });
    expect(view.result.current.isPlaying).toBe(false);
    expect(view.result.current.currentIndex).toBe(2); // seq 3 → index 2
  });

  it("snaps cursor to the last event when filter drops the active step", () => {
    const setSelectedSeq = vi.fn<(seq: number) => void>();
    let selectedSeq: number | null = 5;
    setSelectedSeq.mockImplementation((s) => {
      selectedSeq = s;
    });
    const view = renderHook(
      ({
        events,
        s,
      }: {
        events: readonly LedgerEvent[];
        s: number | null;
      }) =>
        useReplayController({
          events,
          selectedSeq: s,
          setSelectedSeq,
          enabled: true,
        }),
      { initialProps: { events: FIVE, s: selectedSeq } },
    );
    expect(view.result.current.currentIndex).toBe(4);

    // Apply a filter that drops seq=5.
    const filtered = FIVE.slice(0, 3); // seq 1..3
    view.rerender({ events: filtered, s: selectedSeq });
    expect(setSelectedSeq).toHaveBeenLastCalledWith(3);
  });

  it("respects MIN_DELAY_MS lower bound when speed × duration is tiny", () => {
    const events = [makeEvent(1, 10), makeEvent(2, 10)];
    const ctx = setup({ events, initialSeq: 1 });
    act(() => ctx.view.result.current.setMode("realtime"));
    act(() => ctx.view.result.current.setSpeed(8));
    act(() => ctx.view.result.current.play());
    ctx.sync();

    // 10ms duration → clamped to MIN_DELAY_MS (50ms).
    act(() => {
      vi.advanceTimersByTime(MIN_DELAY_MS - 1);
    });
    expect(ctx.setSelectedSeq).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(ctx.setSelectedSeq).toHaveBeenLastCalledWith(2);
  });

  it("progress reflects cursor position", () => {
    const ctx = setup({ initialSeq: 1 });
    expect(ctx.view.result.current.progress).toBe(0);

    const view2 = setup({ initialSeq: 5 });
    expect(view2.view.result.current.progress).toBe(1);

    const view3 = setup({ initialSeq: 3 });
    expect(view3.view.result.current.progress).toBeCloseTo(0.5, 5);
  });
});
