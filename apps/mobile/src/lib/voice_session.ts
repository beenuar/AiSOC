/**
 * The recognise → show → confirm → send flow, as a state machine.
 *
 * Wave 2, Phase 9.1.
 *
 * `voice.ts` shipped the pieces — a recogniser interface that cannot carry
 * audio, `listenForQuestion`, `askByVoice` — and nothing drove them, so
 * there was no screen and nothing could speak to the app. This is the half
 * that was missing, kept out of the React component on purpose: a flow whose
 * states live in a component is testable only by rendering it, and the
 * property that matters here is **which transitions exist**, not what they
 * look like.
 *
 * The transition that must not exist
 * -----------------------------------
 * There is no edge from `listening` to `sending`. On-device recognition is
 * worse than the hosted kind, and a security question misheard is a question
 * answered about the wrong host — "what did db-prod-01 run" and "what did
 * db-prod-07 run" differ by one phoneme and by an entire blast radius. So a
 * transcript always lands in `confirming`, where it can be edited, and
 * `send` is reachable only from there.
 *
 * Refusal is a state, not an error
 * --------------------------------
 * A device with no offline model reaches `unavailable`, which carries the
 * reason and tells the responder to type instead. It is not retried and
 * does not fall back: the hosted recogniser is precisely what this feature
 * promises not to use, and falling back silently would break that promise at
 * the moment the user could least tell.
 */

import {
  OnDeviceRecognitionUnavailable,
  askByVoice,
  listenForQuestion,
  type CopilotAnswer,
  type CopilotClient,
  type SpeechRecogniser,
} from './voice';

export type VoiceState =
  | { phase: 'idle' }
  | { phase: 'listening' }
  /** The transcript is shown here and nowhere else. Editable. */
  | { phase: 'confirming'; transcript: string }
  | { phase: 'sending'; transcript: string }
  | { phase: 'answered'; transcript: string; answer: CopilotAnswer }
  /** The device cannot transcribe locally. Carries why, and does not retry. */
  | { phase: 'unavailable'; reason: string }
  | { phase: 'failed'; reason: string };

export interface VoiceSessionDeps {
  recogniser: SpeechRecogniser;
  copilot: CopilotClient;
  /** Optional on-device speech output. Absent means answers are read, not spoken. */
  speak?: (text: string) => Promise<void>;
}

export class VoiceSession {
  private state: VoiceState = { phase: 'idle' };

  constructor(
    private readonly deps: VoiceSessionDeps,
    private readonly onChange: (state: VoiceState) => void = () => undefined,
  ) {}

  current(): VoiceState {
    return this.state;
  }

  private set(next: VoiceState): VoiceState {
    this.state = next;
    this.onChange(next);
    return next;
  }

  /** Listen, and land on `confirming`. Never on `sending`. */
  async listen(options: { localeTag?: string } = {}): Promise<VoiceState> {
    this.set({ phase: 'listening' });
    try {
      const transcript = await listenForQuestion(this.deps.recogniser, options);
      return this.set({ phase: 'confirming', transcript });
    } catch (err) {
      if (err instanceof OnDeviceRecognitionUnavailable) {
        // Its own phase, so the screen can offer the keyboard rather than a
        // retry button for something retrying will not fix.
        return this.set({ phase: 'unavailable', reason: err.message });
      }
      return this.set({ phase: 'failed', reason: err instanceof Error ? err.message : String(err) });
    }
  }

  /** Correct the transcript before it is sent. */
  edit(transcript: string): VoiceState {
    if (this.state.phase !== 'confirming') {
      return this.set({
        phase: 'failed',
        reason: 'A transcript can only be edited while it is being confirmed.',
      });
    }
    return this.set({ phase: 'confirming', transcript });
  }

  /**
   * Send the confirmed transcript.
   *
   * Reachable only from `confirming`. Calling it from `listening` is a
   * programming error and is refused rather than silently sending whatever
   * the recogniser last produced.
   */
  async send(context: { alertId?: string; caseId?: string } = {}): Promise<VoiceState> {
    if (this.state.phase !== 'confirming') {
      return this.set({
        phase: 'failed',
        reason: 'Nothing has been confirmed to send. A transcript is always shown before it is sent.',
      });
    }
    const transcript = this.state.transcript.trim();
    if (!transcript) {
      return this.set({ phase: 'failed', reason: 'The question is empty.' });
    }

    this.set({ phase: 'sending', transcript });
    try {
      const answer = await askByVoice(this.deps.copilot, transcript, context);
      const next = this.set({ phase: 'answered', transcript, answer });
      if (this.deps.speak) {
        // Spoken output is best-effort: a TTS failure must not discard an
        // answer the responder can read on screen.
        try {
          await this.deps.speak(answer.answer);
        } catch {
          /* the answer is already rendered */
        }
      }
      return next;
    } catch (err) {
      return this.set({ phase: 'failed', reason: err instanceof Error ? err.message : String(err) });
    }
  }

  reset(): VoiceState {
    return this.set({ phase: 'idle' });
  }
}
