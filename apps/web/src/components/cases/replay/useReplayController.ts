/**
 * Replay controller for the investigation ledger (WS-D3).
 *
 * Drives the parent timeline's `selectedSeq` programmatically while playing,
 * supporting two cadences:
 *
 *   - `fixed`     each event holds for FIXED_BASE_MS / speed (default 1s)
 *   - `realtime`  each event holds for its own `duration_ms / speed`,
 *                 clamped to [MIN_DELAY_MS, MAX_DELAY_MS] so demos stay snappy
 *                 even when the agent had a 30s LLM call mid-run
 *
 * The hook is intentionally agnostic about how the parent renders the
 * timeline — it just consumes an ordered events list and the parent's
 * `selectedSeq` setter. That keeps `InvestigationLedger.tsx` free of new
 * playback logic and lets us unit-test the controller in isolation.
 *
 * Auto-pause behavior:
 *   - Reaching the last event pauses (instead of looping).
 *   - Flipping `enabled=false` pauses but preserves the cursor position.
 *   - When the events list shrinks below the cursor (filter change), the
 *     cursor snaps to the new last event.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { LedgerEvent } from "@/lib/api";

export type ReplayMode = "fixed" | "realtime";

export type ReplaySpeed = 0.5 | 1 | 2 | 4 | 8;

export const REPLAY_SPEEDS: readonly ReplaySpeed[] = [0.5, 1, 2, 4, 8] as const;

/** Base cadence (ms) per event in `fixed` mode at 1× speed. */
export const FIXED_BASE_MS = 1000;

/** Lower bound on tick delay so the UI never appears frozen. */
export const MIN_DELAY_MS = 50;

/** Upper bound so a single 30s LLM call doesn't stall replay. */
export const MAX_DELAY_MS = 8000;

export interface ReplayControllerArgs {
  /** Ordered events list (post-filter). Drives playback ordering. */
  events: readonly LedgerEvent[];
  /** Currently highlighted seq in the parent timeline. */
  selectedSeq: number | null;
  /** Setter the parent uses to highlight a step. */
  setSelectedSeq: (seq: number) => void;
  /**
   * Whether replay mode is on. When off, playback halts but the controller
   * keeps its position so toggling back on resumes from the same step.
   */
  enabled: boolean;
}

export interface ReplayController {
  isPlaying: boolean;
  speed: ReplaySpeed;
  mode: ReplayMode;
  /** 0..1 fraction of progress (0 if total <= 1). */
  progress: number;
  /** 0-based index of the current cursor event in `events` (or null). */
  currentIndex: number | null;
  /** Total event count (filtered). */
  total: number;
  // Controls
  play: () => void;
  pause: () => void;
  toggle: () => void;
  /** Pause and reset cursor to the first event. */
  stop: () => void;
  stepForward: () => void;
  stepBackward: () => void;
  seekToIndex: (index: number) => void;
  setSpeed: (s: ReplaySpeed) => void;
  setMode: (m: ReplayMode) => void;
}

export function useReplayController({
  events,
  selectedSeq,
  setSelectedSeq,
  enabled,
}: ReplayControllerArgs): ReplayController {
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState<ReplaySpeed>(1);
  const [mode, setMode] = useState<ReplayMode>("fixed");

  const total = events.length;

  // seq → index lookup, recomputed only when the events list changes. Avoids
  // O(n) work in the playback loop on every tick.
  const seqIndex = useMemo(() => {
    const m = new Map<number, number>();
    events.forEach((e, i) => m.set(e.seq, i));
    return m;
  }, [events]);

  const currentIndex = useMemo(() => {
    if (total === 0 || selectedSeq == null) return null;
    return seqIndex.get(selectedSeq) ?? null;
  }, [selectedSeq, seqIndex, total]);

  // Disabling replay mode pauses without clearing position.
  useEffect(() => {
    if (!enabled && isPlaying) setIsPlaying(false);
  }, [enabled, isPlaying]);

  // If a filter change drops the cursor's event from `events`, snap to last.
  // Without this, replay would silently sit on a no-longer-rendered step.
  useEffect(() => {
    if (
      total > 0 &&
      selectedSeq != null &&
      seqIndex.get(selectedSeq) === undefined
    ) {
      setSelectedSeq(events[total - 1]!.seq);
    }
  }, [total, selectedSeq, seqIndex, events, setSelectedSeq]);

  // Playback loop. Whenever the cursor moves or playback flips on, schedule
  // a single timeout for the next step. We deliberately avoid setInterval —
  // it accumulates drift and ignores per-event duration in `realtime` mode.
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Set by play() when it snaps the cursor back to the first event so the
  // user can replay from the start. The parent's `selectedSeq` prop only
  // updates on the next render cycle, so without this flag the auto-pause
  // branch below would fire on the in-between render where currentIndex
  // still points at the terminal event. Cleared on the first render where
  // currentIndex is no longer terminal.
  const pendingRewindRef = useRef(false);
  useEffect(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    if (!isPlaying || !enabled || total === 0) return;
    if (currentIndex == null) {
      // Playing with nothing selected → snap to first event so the next
      // tick has a defined starting point.
      setSelectedSeq(events[0]!.seq);
      return;
    }
    if (currentIndex >= total - 1) {
      if (pendingRewindRef.current) {
        // The user pressed play at the end; wait one render for the parent
        // to propagate the rewind, then resume normally.
        return;
      }
      // Reached the end — auto-pause rather than loop.
      setIsPlaying(false);
      return;
    }
    // Cursor has advanced past the terminal event — rewind handshake done.
    pendingRewindRef.current = false;
    const here = events[currentIndex]!;
    const baseMs =
      mode === "realtime"
        ? Math.max(MIN_DELAY_MS, here.duration_ms || FIXED_BASE_MS)
        : FIXED_BASE_MS;
    const delay = Math.min(
      MAX_DELAY_MS,
      Math.max(MIN_DELAY_MS, baseMs / speed),
    );
    timeoutRef.current = setTimeout(() => {
      const next = events[currentIndex + 1];
      if (next) setSelectedSeq(next.seq);
    }, delay);

    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };
  }, [
    isPlaying,
    enabled,
    currentIndex,
    total,
    events,
    mode,
    speed,
    setSelectedSeq,
  ]);

  const play = useCallback(() => {
    if (total === 0) return;
    if (currentIndex == null || currentIndex >= total - 1) {
      // Pressing play with nothing selected, or while parked at the end,
      // should restart from the beginning. This matches typical media
      // player UX where ▶ at the end rewinds.
      setSelectedSeq(events[0]!.seq);
      // Tell the playback effect that the impending currentIndex change is
      // expected, so it doesn't auto-pause on the in-between render where
      // selectedSeq still points to the terminal event.
      pendingRewindRef.current = true;
    }
    setIsPlaying(true);
  }, [total, currentIndex, events, setSelectedSeq]);

  const pause = useCallback(() => setIsPlaying(false), []);

  const toggle = useCallback(() => {
    if (isPlaying) setIsPlaying(false);
    else play();
  }, [isPlaying, play]);

  const stop = useCallback(() => {
    setIsPlaying(false);
    if (total > 0) setSelectedSeq(events[0]!.seq);
  }, [total, events, setSelectedSeq]);

  const stepForward = useCallback(() => {
    if (total === 0) return;
    const next =
      currentIndex == null ? 0 : Math.min(currentIndex + 1, total - 1);
    setSelectedSeq(events[next]!.seq);
  }, [currentIndex, total, events, setSelectedSeq]);

  const stepBackward = useCallback(() => {
    if (total === 0) return;
    const prev =
      currentIndex == null ? 0 : Math.max(currentIndex - 1, 0);
    setSelectedSeq(events[prev]!.seq);
  }, [currentIndex, total, events, setSelectedSeq]);

  const seekToIndex = useCallback(
    (index: number) => {
      if (total === 0) return;
      const clamped = Math.max(0, Math.min(index, total - 1));
      setSelectedSeq(events[clamped]!.seq);
    },
    [total, events, setSelectedSeq],
  );

  const progress =
    total <= 1 || currentIndex == null ? 0 : currentIndex / (total - 1);

  return {
    isPlaying,
    speed,
    mode,
    progress,
    currentIndex,
    total,
    play,
    pause,
    toggle,
    stop,
    stepForward,
    stepBackward,
    seekToIndex,
    setSpeed,
    setMode,
  };
}
