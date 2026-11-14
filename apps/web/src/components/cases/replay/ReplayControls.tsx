'use client';

/**
 * Replay controls for the investigation ledger (WS-D3).
 *
 * The visible "tape deck" that drives `useReplayController`. Renders five
 * concerns in a single horizontal strip so it can sit beside the timeline
 * filter toolbar without dominating the screen:
 *
 *   1. Mode toggle — fixed cadence vs realtime (each step's own duration)
 *   2. Transport — step back / play–pause / step forward / stop
 *   3. Speed picker — 0.5×, 1×, 2×, 4×, 8×
 *   4. Scrubber — drag any point in the run; shows "step N of M"
 *   5. Cursor label — current event's seq + summary, for at-a-glance context
 *
 * Styling intentionally mirrors `InvestigationLedger.tsx` toolbars
 * (rounded-xl border-slate-800/80 bg-slate-900/40) so the component slots
 * in without bespoke design tokens.
 */

import { clsx } from 'clsx';
import type { LedgerEvent } from '@/lib/api';
import {
  REPLAY_SPEEDS,
  type ReplayController,
  type ReplaySpeed,
} from './useReplayController';

interface ReplayControlsProps {
  controller: ReplayController;
  /** Event currently under the cursor, used for the trailing label. */
  currentEvent: LedgerEvent | null;
}

const baseBtn =
  'inline-flex items-center justify-center rounded-md border border-slate-700/70 bg-slate-800/50 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-600 disabled:opacity-40 disabled:hover:border-slate-700/70';

const accentBtn =
  'inline-flex items-center justify-center rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-200 hover:border-emerald-400/60 disabled:opacity-40 disabled:hover:border-emerald-500/40';

export function ReplayControls({ controller, currentEvent }: ReplayControlsProps) {
  // We deliberately use `toggle` for the play/pause button rather than
  // destructuring `play`/`pause` separately — keeps the click handler simple
  // and makes the play→pause→play cycle feel like a single keyboard target.
  const {
    isPlaying,
    speed,
    mode,
    progress,
    currentIndex,
    total,
    toggle,
    stop,
    stepForward,
    stepBackward,
    seekToIndex,
    setSpeed,
    setMode,
  } = controller;

  const disabled = total === 0;
  // Scrubber uses 0..total-1 indices (clamped). A single-event run still
  // renders the slider (max=0) but it can't be dragged — that's fine; the
  // cursor label still gives the operator something to look at.
  const scrubberMax = Math.max(0, total - 1);
  const scrubberValue = currentIndex ?? 0;

  return (
    <div
      className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800/80 bg-slate-900/40 px-3 py-2"
      role="region"
      aria-label="Investigation replay controls"
    >
      {/* Mode toggle — fixed vs realtime */}
      <div className="flex items-center gap-1 rounded-md border border-slate-700/70 bg-slate-900/60 p-0.5">
        <ModeButton
          active={mode === 'fixed'}
          onClick={() => setMode('fixed')}
          title="Fixed 1s cadence per step (good for screen recording)"
        >
          Fixed
        </ModeButton>
        <ModeButton
          active={mode === 'realtime'}
          onClick={() => setMode('realtime')}
          title="Use each step's own duration (real agent pacing, clamped 50–8000ms)"
        >
          Realtime
        </ModeButton>
      </div>

      {/* Transport */}
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={stepBackward}
          disabled={disabled || (currentIndex ?? 0) <= 0}
          className={baseBtn}
          aria-label="Step backward"
          title="Previous step"
        >
          ◀︎
        </button>
        <button
          type="button"
          onClick={toggle}
          disabled={disabled}
          className={accentBtn}
          aria-label={isPlaying ? 'Pause replay' : 'Play replay'}
          aria-pressed={isPlaying}
          title={isPlaying ? 'Pause' : 'Play'}
        >
          {isPlaying ? '⏸︎ Pause' : '▶︎ Play'}
        </button>
        <button
          type="button"
          onClick={stepForward}
          disabled={disabled || (currentIndex ?? -1) >= total - 1}
          className={baseBtn}
          aria-label="Step forward"
          title="Next step"
        >
          ▶︎
        </button>
        <button
          type="button"
          onClick={stop}
          disabled={disabled}
          className={baseBtn}
          aria-label="Stop and rewind"
          title="Rewind to first step"
        >
          ⏮︎
        </button>
      </div>

      {/* Speed picker */}
      <div className="flex items-center gap-1">
        <span className="text-[11px] uppercase tracking-wide text-slate-500">
          Speed
        </span>
        <select
          value={String(speed)}
          onChange={(e) => setSpeed(Number(e.target.value) as ReplaySpeed)}
          disabled={disabled}
          className="rounded-md border border-slate-700/70 bg-slate-900/60 px-2 py-1.5 text-xs text-slate-200 focus:border-emerald-500/40 focus:outline-none"
          aria-label="Replay speed"
        >
          {REPLAY_SPEEDS.map((s) => (
            <option key={s} value={String(s)}>
              {s}×
            </option>
          ))}
        </select>
      </div>

      {/* Scrubber + cursor label fill remaining space */}
      <div className="ml-auto flex min-w-[260px] flex-1 items-center gap-2">
        <input
          type="range"
          min={0}
          max={scrubberMax}
          step={1}
          value={scrubberValue}
          onChange={(e) => seekToIndex(Number(e.target.value))}
          disabled={disabled || total <= 1}
          aria-label="Seek to step"
          className="h-1.5 w-full cursor-pointer appearance-none rounded-full bg-slate-800 accent-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
          // Browsers don't expose progress styling for native range inputs, so
          // a simple gradient fills the played portion to the left of the
          // thumb. Falls back gracefully when the slider is disabled.
          style={
            !disabled && total > 1
              ? {
                  background: `linear-gradient(to right, rgb(16 185 129 / 0.6) 0%, rgb(16 185 129 / 0.6) ${
                    progress * 100
                  }%, rgb(15 23 42) ${progress * 100}%, rgb(15 23 42) 100%)`,
                }
              : undefined
          }
        />
        <span
          className={clsx(
            'whitespace-nowrap text-[11px] tabular-nums',
            disabled ? 'text-slate-600' : 'text-slate-400',
          )}
        >
          {disabled
            ? 'No events'
            : `Step ${(currentIndex ?? 0) + 1} of ${total}`}
        </span>
      </div>

      {/* Current event hint — full-width on small screens, inline on wide */}
      {currentEvent && (
        <div className="basis-full pt-1 text-[11px] text-slate-500">
          <span className="font-mono text-slate-400">#{currentEvent.seq}</span>{' '}
          <span className="uppercase tracking-wide text-slate-500">
            {currentEvent.kind.replace(/_/g, ' ')}
          </span>{' '}
          <span className="text-slate-400">·</span>{' '}
          <span className="text-slate-300">{currentEvent.agent}</span>
          {currentEvent.summary && (
            <>
              {' '}
              <span className="text-slate-400">·</span>{' '}
              <span className="text-slate-400">{currentEvent.summary}</span>
            </>
          )}
        </div>
      )}

      {/* Live-region hint so screen readers announce the playback transition
          without us having to wire a separate aria-live element. */}
      <span className="sr-only" aria-live="polite">
        {isPlaying ? 'Replay playing' : 'Replay paused'}
      </span>
    </div>
  );
}

interface ModeButtonProps {
  active: boolean;
  onClick: () => void;
  title?: string;
  children: React.ReactNode;
}

function ModeButton({ active, onClick, title, children }: ModeButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      aria-pressed={active}
      className={clsx(
        'rounded px-2 py-1 text-[11px] font-medium transition-colors',
        active
          ? 'bg-emerald-500/15 text-emerald-200 ring-1 ring-inset ring-emerald-500/30'
          : 'text-slate-400 hover:text-slate-200',
      )}
    >
      {children}
    </button>
  );
}
