/**
 * The console reaches the agents service through Next rewrites, whose proxy
 * times out at 30 s unless `experimental.proxyTimeout` is set. Copilot's model
 * call has a 30 s budget of its own and falls back to a labelled template
 * after it, so with the default the proxy always dropped the connection
 * first ("Failed to proxy http://agents:8084/api/v1/copilot/chat: socket hang
 * up") and the analyst saw a 500 instead of the fallback.
 */
import { createRequire } from 'node:module';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);
const COPILOT_MODEL_BUDGET_MS = 30_000;

function loadConfig(): { experimental?: { proxyTimeout?: number } } {
  const file = path.join(process.cwd(), 'next.config.js');
  delete require.cache[file];
  return require(file);
}

describe('next.config proxy timeout', () => {
  it('outlasts the Copilot model budget with room for the fallback reply', () => {
    const timeout = loadConfig().experimental?.proxyTimeout ?? 30_000;
    expect(timeout).toBeGreaterThanOrEqual(COPILOT_MODEL_BUDGET_MS * 2);
  });

  it('can be raised for slower deployments', () => {
    const before = process.env.AISOC_PROXY_TIMEOUT_MS;
    process.env.AISOC_PROXY_TIMEOUT_MS = '300000';
    try {
      expect(loadConfig().experimental?.proxyTimeout).toBe(300_000);
    } finally {
      if (before === undefined) delete process.env.AISOC_PROXY_TIMEOUT_MS;
      else process.env.AISOC_PROXY_TIMEOUT_MS = before;
    }
  });
});
