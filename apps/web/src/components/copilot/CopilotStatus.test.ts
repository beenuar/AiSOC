/**
 * The copilot header pill had two states and both were wrong.
 *
 * A green dot reading "Connected" rendered before any request had been made,
 * so it asserted connectivity it had not tested. And **any** error — a 500, an
 * expired session, a dropped connection — flipped it to "Demo mode", on
 * deployments that are not the demo. That tells an operator their platform is
 * in a mode it does not have, while the real cause goes unnamed.
 */

import { describe, expect, it } from 'vitest';
import { ApiError } from '@/lib/api';
import { copilotStatus } from './CopilotView';

const base = {
  sendError: null as unknown,
  conversationsError: null as unknown,
  conversationsLoaded: false,
  everSucceeded: false,
  demo: false,
};

describe('copilotStatus', () => {
  it('claims nothing before a request has completed', () => {
    const status = copilotStatus(base);

    expect(status.tone).toBe('unknown');
    expect(status.label).not.toMatch(/connected/i);
    expect(status.detail).toMatch(/untested/i);
  });

  it('says Connected once a request has actually succeeded', () => {
    expect(copilotStatus({ ...base, everSucceeded: true }).tone).toBe('ok');
    // Listing conversations resolving is also evidence — it is a real round
    // trip to the same backend.
    expect(copilotStatus({ ...base, conversationsLoaded: true }).tone).toBe('ok');
  });

  it('does not call a backend failure "Demo mode" outside the demo', () => {
    const status = copilotStatus({ ...base, sendError: new ApiError('API 500', 500, '') });

    expect(status.label).not.toMatch(/demo/i);
    expect(status.label).toMatch(/failed/i);
    expect(status.detail).toMatch(/returned 500/i);
  });

  it('names an expired session as one rather than as an outage', () => {
    const status = copilotStatus({ ...base, sendError: new ApiError('API 401', 401, '') });

    expect(status.detail).toMatch(/sign in again/i);
    expect(status.label).not.toMatch(/demo/i);
  });

  it('calls a 422 a console bug, not an outage and not demo mode', () => {
    const status = copilotStatus({ ...base, sendError: new ApiError('API 422', 422, '') });

    expect(status.detail).toMatch(/console bug rather than an outage/i);
  });

  it('only mentions the demo when the deployment really is the demo', () => {
    // There it is true and load-bearing: a scripted reply was substituted, and
    // the pill is the only thing that says so.
    const status = copilotStatus({
      ...base,
      demo: true,
      sendError: new ApiError('API 500', 500, ''),
    });

    expect(status.label).toMatch(/demo reply/i);
    expect(status.detail).toMatch(/built-in demo script/i);
  });

  it('separates "history unavailable" from "the copilot is down"', () => {
    // Listing conversations and answering a question are different endpoints;
    // one failing does not prove the other is down.
    const status = copilotStatus({
      ...base,
      conversationsError: new ApiError('API 500', 500, ''),
    });

    expect(status.label).toMatch(/history unavailable/i);
    expect(status.detail).toMatch(/conversation history/i);
  });

  it('prefers the send failure when both have failed, because it is the one the analyst hit', () => {
    const status = copilotStatus({
      ...base,
      sendError: new ApiError('API 503', 503, ''),
      conversationsError: new ApiError('API 500', 500, ''),
    });

    expect(status.label).toMatch(/last message failed/i);
  });

  it('never renders a green dot while something is failing', () => {
    const failures = [
      { ...base, sendError: new ApiError('API 500', 500, ''), everSucceeded: true },
      { ...base, conversationsError: new ApiError('API 500', 500, ''), conversationsLoaded: true },
    ];
    for (const args of failures) {
      expect(copilotStatus(args).tone).toBe('failed');
    }
  });
});
