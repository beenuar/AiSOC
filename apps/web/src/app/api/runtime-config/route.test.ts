/**
 * `consoleVersion` must never be an empty string.
 *
 * `next.config.js` substitutes `NEXT_PUBLIC_APP_VERSION` at build time, so by
 * the time this route runs the variable is always *present* — the question is
 * only whether it has content. It previously substituted `'0.0.0'` when the
 * repo-root VERSION file could not be read, which made this route's
 * `'unknown'` fallback unreachable and put a version-shaped placeholder on
 * two console surfaces. The fallback is now `''`, so the guard here has to be
 * `||` rather than `??`: `??` treats an empty string as an answer and
 * publishes it, and an empty version renders as nothing at all, which reads
 * as a layout bug rather than a missing value.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

const ORIGINAL = process.env.NEXT_PUBLIC_APP_VERSION;

afterEach(() => {
  if (ORIGINAL === undefined) delete process.env.NEXT_PUBLIC_APP_VERSION;
  else process.env.NEXT_PUBLIC_APP_VERSION = ORIGINAL;
  vi.resetModules();
});

async function readBody() {
  vi.resetModules();
  const { GET } = await import('./route');
  return (await GET().json()) as { consoleVersion: string };
}

describe('GET /api/runtime-config → consoleVersion', () => {
  it('serves the version the bundle was built from', async () => {
    process.env.NEXT_PUBLIC_APP_VERSION = '22.2.0';
    expect((await readBody()).consoleVersion).toBe('22.2.0');
  });

  it('serves "unknown" when the build carried no version', async () => {
    process.env.NEXT_PUBLIC_APP_VERSION = '';
    expect((await readBody()).consoleVersion).toBe('unknown');
  });

  it('serves "unknown" when the variable is absent entirely', async () => {
    delete process.env.NEXT_PUBLIC_APP_VERSION;
    expect((await readBody()).consoleVersion).toBe('unknown');
  });

  it('never serves an empty string', async () => {
    for (const value of ['', '   ']) {
      process.env.NEXT_PUBLIC_APP_VERSION = value;
      expect((await readBody()).consoleVersion.trim()).not.toBe('');
    }
  });
});
