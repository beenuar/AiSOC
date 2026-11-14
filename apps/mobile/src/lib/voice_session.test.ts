/**
 * The voice flow, and the transition that must not exist.
 *
 * Wave 2, Phase 9.1.
 *
 * The property this file is really about: **a transcript is always shown
 * before it is sent.** On-device recognition is worse than the hosted kind,
 * and a security question misheard is a question answered about the wrong
 * host — "db-prod-01" and "db-prod-07" differ by one phoneme and by an
 * entire blast radius. So `listening` never reaches `sending`, and `send`
 * refuses from any phase but `confirming`.
 *
 * The second property is the refusal. A device with no offline model gets
 * its own phase carrying the reason, and the flow does not fall back to the
 * hosted recogniser — which is the one thing this feature promises not to
 * use, and the moment the user could least tell.
 */

import { describe, expect, it, vi } from 'vitest';

import { OnDeviceRecognitionUnavailable, type CopilotClient, type SpeechRecogniser } from './voice';
import { VoiceSession, type VoiceState } from './voice_session';

function recogniser(overrides: Partial<SpeechRecogniser> = {}): SpeechRecogniser {
  return {
    isOnDeviceAvailable: vi.fn(async () => true),
    transcribe: vi.fn(async () => 'what did db-prod-01 run'),
    stop: vi.fn(async () => undefined),
    ...overrides,
  };
}

function copilot(answer = 'It ran a backup job.'): CopilotClient {
  return { ask: vi.fn(async () => ({ answer })) };
}

describe('VoiceSession', () => {
  it('lands on confirming, never on sending', async () => {
    const session = new VoiceSession({ recogniser: recogniser(), copilot: copilot() });
    const state = await session.listen();
    expect(state.phase).toBe('confirming');
    expect(state).toMatchObject({ transcript: 'what did db-prod-01 run' });
  });

  it('records every phase it passed through, and sending is not among them', async () => {
    const seen: VoiceState['phase'][] = [];
    const session = new VoiceSession(
      { recogniser: recogniser(), copilot: copilot() },
      (s) => seen.push(s.phase),
    );
    await session.listen();
    // The whole point: there is no edge from listening to sending.
    expect(seen).toEqual(['listening', 'confirming']);
    expect(seen).not.toContain('sending');
  });

  it('refuses to send anything that was not confirmed', async () => {
    const client = copilot();
    const session = new VoiceSession({ recogniser: recogniser(), copilot: client });
    const state = await session.send();
    expect(state.phase).toBe('failed');
    expect(state).toMatchObject({ reason: expect.stringContaining('always shown before it is sent') });
    // Nothing reached the copilot.
    expect(client.ask).not.toHaveBeenCalled();
  });

  it('lets the transcript be corrected before it is sent', async () => {
    const client = copilot();
    const session = new VoiceSession({ recogniser: recogniser(), copilot: client });
    await session.listen();
    session.edit('what did db-prod-07 run');
    await session.send({ alertId: 'a1' });
    expect(client.ask).toHaveBeenCalledWith('what did db-prod-07 run', { alertId: 'a1' });
  });

  it('refuses an edit outside the confirming phase', async () => {
    const session = new VoiceSession({ recogniser: recogniser(), copilot: copilot() });
    expect(session.edit('anything').phase).toBe('failed');
  });

  it('gives a device with no offline model its own phase, and does not retry', async () => {
    const rec = recogniser({ isOnDeviceAvailable: vi.fn(async () => false) });
    const client = copilot();
    const session = new VoiceSession({ recogniser: rec, copilot: client });
    const state = await session.listen();

    expect(state.phase).toBe('unavailable');
    expect(state).toMatchObject({ reason: expect.stringContaining('on-device') });
    // Not a fallback: the hosted recogniser is what this promises not to use.
    expect(rec.transcribe).not.toHaveBeenCalled();
    expect(client.ask).not.toHaveBeenCalled();
  });

  it('treats an empty recognition as a failure, not as an empty question', async () => {
    const rec = recogniser({ transcribe: vi.fn(async () => '   ') });
    const session = new VoiceSession({ recogniser: rec, copilot: copilot() });
    const state = await session.listen();
    expect(state.phase).toBe('failed');
  });

  it('surfaces a copilot failure rather than inventing an answer', async () => {
    const client: CopilotClient = {
      ask: vi.fn(async () => {
        throw new Error('copilot unreachable');
      }),
    };
    const session = new VoiceSession({ recogniser: recogniser(), copilot: client });
    await session.listen();
    const state = await session.send();
    expect(state.phase).toBe('failed');
    expect(state).toMatchObject({ reason: expect.stringContaining('copilot unreachable') });
  });

  it('speaks the answer when a speech output is provided', async () => {
    const speak = vi.fn(async () => undefined);
    const session = new VoiceSession({ recogniser: recogniser(), copilot: copilot('All clear.'), speak });
    await session.listen();
    await session.send();
    expect(speak).toHaveBeenCalledWith('All clear.');
  });

  it('keeps the answer when speaking it fails', async () => {
    const speak = vi.fn(async () => {
      throw new Error('no voice installed');
    });
    const session = new VoiceSession({ recogniser: recogniser(), copilot: copilot(), speak });
    await session.listen();
    const state = await session.send();
    // A TTS failure must not discard an answer the responder can read.
    expect(state.phase).toBe('answered');
  });

  it('exposes the unavailable reason as the message the user is shown', async () => {
    const error = new OnDeviceRecognitionUnavailable('no offline model');
    expect(error.message).toContain('will not send your microphone audio anywhere');
  });
});
