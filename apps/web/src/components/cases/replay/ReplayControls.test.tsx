import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ReplayControls } from './ReplayControls';
import type { ReplayController } from './useReplayController';
import type { LedgerEvent } from '@/lib/api';

// The hook is unit-tested in `useReplayController.test.ts`; here we just
// assert that the component wires its props onto the visible control surface
// (transport, scrubber, mode, speed) and forwards user input back to the
// controller. We pass a hand-rolled controller mock instead of rendering the
// real hook so we can isolate UI behaviour from playback timing.

function makeController(over: Partial<ReplayController> = {}): ReplayController {
  return {
    isPlaying: false,
    speed: 1,
    mode: 'fixed',
    progress: 0,
    currentIndex: 0,
    total: 5,
    play: vi.fn(),
    pause: vi.fn(),
    toggle: vi.fn(),
    stop: vi.fn(),
    stepForward: vi.fn(),
    stepBackward: vi.fn(),
    seekToIndex: vi.fn(),
    setSpeed: vi.fn(),
    setMode: vi.fn(),
    ...over,
  };
}

function makeEvent(seq: number, summary = `step ${seq}`): LedgerEvent {
  return {
    id: `evt-${seq}`,
    run_id: 'run-1',
    seq,
    ts: '2026-05-09T00:00:00Z',
    kind: 'tool_call',
    agent: 'investigator',
    summary,
    payload: null,
    input_hash: null,
    output_hash: null,
    duration_ms: 1000,
  };
}

describe('ReplayControls', () => {
  it('renders the play button when paused and forwards toggle()', async () => {
    const controller = makeController({ isPlaying: false });
    render(<ReplayControls controller={controller} currentEvent={makeEvent(1)} />);

    const play = screen.getByRole('button', { name: 'Play replay' });
    expect(play).toHaveAttribute('aria-pressed', 'false');
    await userEvent.click(play);
    expect(controller.toggle).toHaveBeenCalledTimes(1);
  });

  it('renders the pause button when playing and reflects aria-pressed', () => {
    const controller = makeController({ isPlaying: true });
    render(<ReplayControls controller={controller} currentEvent={makeEvent(2)} />);
    const pause = screen.getByRole('button', { name: 'Pause replay' });
    expect(pause).toHaveAttribute('aria-pressed', 'true');
    expect(pause).toHaveTextContent(/Pause/i);
  });

  it('disables ◀︎ at the start and ▶︎ at the end', () => {
    const atStart = makeController({ currentIndex: 0, total: 5 });
    const { rerender } = render(
      <ReplayControls controller={atStart} currentEvent={makeEvent(1)} />,
    );
    expect(screen.getByRole('button', { name: 'Step backward' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Step forward' })).not.toBeDisabled();

    const atEnd = makeController({ currentIndex: 4, total: 5 });
    rerender(<ReplayControls controller={atEnd} currentEvent={makeEvent(5)} />);
    expect(screen.getByRole('button', { name: 'Step backward' })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: 'Step forward' })).toBeDisabled();
  });

  it('disables every transport button when total is 0', () => {
    const controller = makeController({ total: 0, currentIndex: null });
    render(<ReplayControls controller={controller} currentEvent={null} />);
    expect(screen.getByRole('button', { name: 'Play replay' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Step backward' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Step forward' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Stop and rewind' })).toBeDisabled();
    expect(screen.getByText('No events')).toBeInTheDocument();
  });

  it('forwards step + stop callbacks to the controller', async () => {
    const controller = makeController({ currentIndex: 2, total: 5 });
    render(<ReplayControls controller={controller} currentEvent={makeEvent(3)} />);

    await userEvent.click(screen.getByRole('button', { name: 'Step backward' }));
    await userEvent.click(screen.getByRole('button', { name: 'Step forward' }));
    await userEvent.click(screen.getByRole('button', { name: 'Stop and rewind' }));
    expect(controller.stepBackward).toHaveBeenCalledTimes(1);
    expect(controller.stepForward).toHaveBeenCalledTimes(1);
    expect(controller.stop).toHaveBeenCalledTimes(1);
  });

  it('drives the speed picker with the active speed', async () => {
    const controller = makeController({ speed: 2 });
    render(<ReplayControls controller={controller} currentEvent={makeEvent(1)} />);

    const select = screen.getByLabelText('Replay speed') as HTMLSelectElement;
    expect(select.value).toBe('2');
    await userEvent.selectOptions(select, '4');
    expect(controller.setSpeed).toHaveBeenLastCalledWith(4);
  });

  it('toggles between fixed and realtime mode', async () => {
    const controller = makeController({ mode: 'fixed' });
    render(<ReplayControls controller={controller} currentEvent={makeEvent(1)} />);

    const fixedBtn = screen.getByRole('button', { name: 'Fixed' });
    const realtimeBtn = screen.getByRole('button', { name: 'Realtime' });
    expect(fixedBtn).toHaveAttribute('aria-pressed', 'true');
    expect(realtimeBtn).toHaveAttribute('aria-pressed', 'false');

    await userEvent.click(realtimeBtn);
    expect(controller.setMode).toHaveBeenLastCalledWith('realtime');
  });

  it('drives the scrubber with the controller index and seeks on input', () => {
    const controller = makeController({ currentIndex: 3, total: 5, progress: 0.75 });
    render(<ReplayControls controller={controller} currentEvent={makeEvent(4)} />);

    const slider = screen.getByLabelText('Seek to step') as HTMLInputElement;
    expect(slider.value).toBe('3');
    expect(slider.max).toBe('4'); // total - 1
    expect(slider.min).toBe('0');

    // userEvent.type doesn't reliably drive native ranges in jsdom — fire a
    // testing-library synthetic change so React picks it up via SyntheticEvent.
    fireEvent.change(slider, { target: { value: '1' } });
    expect(controller.seekToIndex).toHaveBeenLastCalledWith(1);

    expect(screen.getByText('Step 4 of 5')).toBeInTheDocument();
  });

  it('disables the scrubber when there is only one event', () => {
    const controller = makeController({ currentIndex: 0, total: 1 });
    render(<ReplayControls controller={controller} currentEvent={makeEvent(1)} />);
    expect(screen.getByLabelText('Seek to step')).toBeDisabled();
    expect(screen.getByText('Step 1 of 1')).toBeInTheDocument();
  });

  it('shows the current event hint when one is provided', () => {
    const controller = makeController({ currentIndex: 1, total: 5 });
    const evt = makeEvent(2, 'Pulled the failing pod logs');
    render(<ReplayControls controller={controller} currentEvent={evt} />);

    expect(screen.getByText('#2')).toBeInTheDocument();
    expect(screen.getByText(/tool call/i)).toBeInTheDocument();
    expect(screen.getByText('investigator')).toBeInTheDocument();
    expect(screen.getByText('Pulled the failing pod logs')).toBeInTheDocument();
  });

  it('omits the event hint when nothing is selected', () => {
    const controller = makeController({ total: 5, currentIndex: 0 });
    render(<ReplayControls controller={controller} currentEvent={null} />);
    expect(screen.queryByText('#1')).not.toBeInTheDocument();
  });

  it('exposes a screen-reader-only live status for play/pause transitions', () => {
    const controller = makeController({ isPlaying: false });
    const { rerender } = render(
      <ReplayControls controller={controller} currentEvent={makeEvent(1)} />,
    );
    expect(screen.getByText('Replay paused')).toBeInTheDocument();
    const playing = makeController({ isPlaying: true });
    rerender(<ReplayControls controller={playing} currentEvent={makeEvent(1)} />);
    expect(screen.getByText('Replay playing')).toBeInTheDocument();
  });
});
