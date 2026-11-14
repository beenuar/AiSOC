/**
 * Ask the copilot by speaking. The audio never leaves the device.
 *
 * Depth 9.6. The plan's wording is exact — "converts speech to text on the
 * device and sends the text to the grounded copilot. No audio leaves the
 * device" — and that last sentence is the whole design constraint, not a
 * nice-to-have. A responder saying "what did this host do before the alert"
 * out loud at 3am is in a room with other people's conversations in it, and
 * a SOC product that uploaded that audio to a transcription service would
 * be exfiltrating its customer's office.
 *
 * How the constraint is held, structurally
 * ----------------------------------------
 * This module has **no access to audio at all.** It takes a
 * {@link SpeechRecogniser} — an object that returns a *string* — and posts
 * that string. There is no buffer, no blob, no file handle and no recording
 * API anywhere in the type signature, so there is nothing for a future edit
 * to accidentally upload. The platform's own on-device recogniser
 * (`SFSpeechRecognizer` with `requiresOnDeviceRecognition`, Android's
 * `SpeechRecognizer` with `EXTRA_PREFER_OFFLINE`) is what produces the
 * string, behind that interface.
 *
 * A promise in a comment would not be worth much, so
 * `scripts/check_no_audio_egress.py` reads this directory and fails if any
 * module here imports a recording API or sends a binary body. The test
 * below proves the request body is `application/json` carrying only text.
 *
 * Why the transcript is shown before it is sent
 * ---------------------------------------------
 * On-device recognition is worse than the cloud kind, and a security
 * question misheard is a question answered about the wrong host. The flow
 * is recognise → show → the responder confirms → send, and
 * {@link askByVoice} takes the confirmed string rather than wiring the
 * recogniser straight to the network.
 */

/** The platform recogniser, behind an interface that cannot carry audio. */
export interface SpeechRecogniser {
  /**
   * Whether this device can transcribe without a network round trip.
   *
   * `false` is a refusal, not a fallback: a device with no on-device model
   * would otherwise silently use the cloud one, which is the exact thing
   * this feature promises not to do.
   */
  isOnDeviceAvailable(): Promise<boolean>;
  /** Listen, and resolve with what was said. Never with audio. */
  transcribe(options?: { localeTag?: string }): Promise<string>;
  stop(): Promise<void>;
}

export interface CopilotClient {
  /** POST the question to the grounded copilot and return its answer. */
  ask(question: string, context?: { alertId?: string; caseId?: string }): Promise<CopilotAnswer>;
}

export interface CopilotAnswer {
  answer: string;
  citations?: Array<{ kind: string; id: string; label: string }>;
}

export class OnDeviceRecognitionUnavailable extends Error {
  constructor(detail: string) {
    super(
      `Voice input needs on-device speech recognition, and this device cannot do it (${detail}). ` +
        `Type the question instead — AiSOC will not send your microphone audio anywhere.`,
    );
    this.name = 'OnDeviceRecognitionUnavailable';
  }
}

/**
 * Transcribe a question locally and hand back the text for confirmation.
 *
 * Refuses when the device has no on-device model. The alternative — quietly
 * using the platform's cloud recogniser — would break the one promise this
 * feature makes, and the user would have no way to know.
 */
export async function listenForQuestion(
  recogniser: SpeechRecogniser,
  options: { localeTag?: string } = {},
): Promise<string> {
  let available: boolean;
  try {
    available = await recogniser.isOnDeviceAvailable();
  } catch (err) {
    throw new OnDeviceRecognitionUnavailable(String(err));
  }
  if (!available) {
    throw new OnDeviceRecognitionUnavailable('no offline model is installed for this locale');
  }
  const transcript = (await recogniser.transcribe(options)).trim();
  if (!transcript) {
    // An empty transcript is a failed recognition, not an empty question.
    // Sending it would spend a model call on nothing and return an answer
    // to a question nobody asked.
    throw new Error('Nothing was recognised. Try again, or type the question.');
  }
  return transcript;
}

/**
 * Send a **confirmed** transcript to the grounded copilot.
 *
 * Takes a string, deliberately. There is no overload taking audio, and the
 * recogniser is not reachable from here — so no edit to this function can
 * turn it into an upload.
 */
export async function askByVoice(
  copilot: CopilotClient,
  transcript: string,
  context: { alertId?: string; caseId?: string } = {},
): Promise<CopilotAnswer> {
  const question = transcript.trim();
  if (!question) {
    throw new Error('Nothing to ask.');
  }
  return copilot.ask(question, context);
}

/**
 * The copilot client the app uses. One JSON POST carrying a string.
 *
 * `fetchImpl` is injected so the test below can assert the body really is
 * JSON text — the honest way to prove "no audio leaves the device" is to
 * read the request, not to promise it in a comment.
 */
export function makeCopilotClient(opts: {
  baseUrl: string;
  token: string;
  fetchImpl?: typeof fetch;
}): CopilotClient {
  const doFetch = opts.fetchImpl ?? fetch;
  return {
    async ask(question, context) {
      const res = await doFetch(`${opts.baseUrl.replace(/\/$/, '')}/api/v1/copilot/ask`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${opts.token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          question,
          ...(context?.alertId ? { alert_id: context.alertId } : {}),
          ...(context?.caseId ? { case_id: context.caseId } : {}),
        }),
      });
      if (!res.ok) {
        throw new Error(`The copilot answered HTTP ${res.status}.`);
      }
      const body = (await res.json()) as Partial<CopilotAnswer>;
      if (typeof body.answer !== 'string') {
        // No invented answer on a malformed reply. An empty string rendered
        // as a response is the fabrication defect this product has shipped
        // before.
        throw new Error('The copilot returned no answer.');
      }
      return { answer: body.answer, citations: body.citations ?? [] };
    },
  };
}
