/**
 * Voice input: the audio never leaves the device, and the proof is the request.
 *
 * Depth 9.6. Asserted by name below:
 *
 * * the request body is JSON carrying **only the transcript** — asserted
 *   against the captured request rather than promised in a comment, because
 *   a promise in a comment is what this repository keeps finding to be
 *   false;
 * * a device with no offline model is **refused**, not quietly switched to
 *   the platform's cloud recogniser, which would break the one promise this
 *   feature makes with no way for the user to know;
 * * an empty transcript is a failed recognition, not an empty question;
 * * a malformed copilot reply raises rather than rendering an empty answer.
 */

import { describe, expect, it, vi } from 'vitest';

import {
  OnDeviceRecognitionUnavailable,
  askByVoice,
  listenForQuestion,
  makeCopilotClient,
  type SpeechRecogniser,
} from './voice';

function recogniser(overrides: Partial<SpeechRecogniser> = {}): SpeechRecogniser {
  return {
    isOnDeviceAvailable: async () => true,
    transcribe: async () => 'what did WKS 14 do before the alert',
    stop: async () => {},
    ...overrides,
  };
}

describe('listenForQuestion', () => {
  it('returns the transcript when the device can transcribe locally', async () => {
    await expect(listenForQuestion(recogniser())).resolves.toBe(
      'what did WKS 14 do before the alert',
    );
  });

  it('refuses a device with no offline model rather than using the cloud one', async () => {
    const spoke = vi.fn();
    await expect(
      listenForQuestion(recogniser({ isOnDeviceAvailable: async () => false, transcribe: spoke })),
    ).rejects.toBeInstanceOf(OnDeviceRecognitionUnavailable);
    // And it never even listened: refusing after recording would mean audio
    // existed on the device for no reason.
    expect(spoke).not.toHaveBeenCalled();
  });

  it('says what to do instead, and says the audio is not sent anywhere', async () => {
    await expect(
      listenForQuestion(recogniser({ isOnDeviceAvailable: async () => false })),
    ).rejects.toThrow(/Type the question instead/);
    await expect(
      listenForQuestion(recogniser({ isOnDeviceAvailable: async () => false })),
    ).rejects.toThrow(/will not send your microphone audio anywhere/);
  });

  it('treats an empty transcript as a failed recognition', async () => {
    await expect(listenForQuestion(recogniser({ transcribe: async () => '   ' }))).rejects.toThrow(
      /Nothing was recognised/,
    );
  });
});

describe('askByVoice', () => {
  it('sends JSON carrying only the transcript — nothing binary, no audio field', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: unknown, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify({ answer: 'It spawned powershell from winword.' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;

    const copilot = makeCopilotClient({ baseUrl: 'https://aisoc.example/', token: 'tok', fetchImpl });
    const answer = await askByVoice(copilot, '  what did WKS 14 do  ', { alertId: 'a-1' });

    expect(answer.answer).toBe('It spawned powershell from winword.');
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://aisoc.example/api/v1/copilot/ask');

    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers['content-type']).toBe('application/json');

    const body = calls[0].init.body;
    // A string body, not a Blob, a FormData or an ArrayBuffer. This is the
    // assertion that makes "no audio leaves the device" checkable rather
    // than stated.
    expect(typeof body).toBe('string');
    const parsed = JSON.parse(String(body));
    expect(Object.keys(parsed).sort()).toEqual(['alert_id', 'question']);
    expect(parsed.question).toBe('what did WKS 14 do');
  });

  it('refuses to spend a model call on an empty question', async () => {
    const fetchImpl = vi.fn();
    const copilot = makeCopilotClient({
      baseUrl: 'https://aisoc.example',
      token: 't',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    await expect(askByVoice(copilot, '   ')).rejects.toThrow(/Nothing to ask/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('raises on a malformed reply rather than rendering an empty answer', async () => {
    const fetchImpl = (async () =>
      new Response(JSON.stringify({ unexpected: true }), { status: 200 })) as unknown as typeof fetch;
    const copilot = makeCopilotClient({ baseUrl: 'https://aisoc.example', token: 't', fetchImpl });
    await expect(askByVoice(copilot, 'anything')).rejects.toThrow(/no answer/);
  });

  it('surfaces an HTTP failure rather than an invented answer', async () => {
    const fetchImpl = (async () => new Response('upstream exploded', { status: 502 })) as unknown as typeof fetch;
    const copilot = makeCopilotClient({ baseUrl: 'https://aisoc.example', token: 't', fetchImpl });
    await expect(askByVoice(copilot, 'anything')).rejects.toThrow(/HTTP 502/);
  });
});
