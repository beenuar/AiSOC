/**
 * The console's default tenant reference has to be resolvable.
 *
 * `next.config.js` inlined `NEXT_PUBLIC_TENANT_ID` with a fallback of the
 * *slug* `'default'`. Three tenant-scoped surfaces pass that value as a query
 * parameter to a route that declares a UUID — `/fusion/entity-risk/queue`,
 * `/honeytokens/*` and `/business-context/*` — and all three answered 422.
 *
 * Two things made it hard to see. `api.ts` carries the correct canonical UUID
 * as its own fallback, so reading it suggested the console was already doing
 * the right thing; but Next's inlining runs first, so that fallback was
 * unreachable code. And the slug is not a dependable handle either: migration
 * 001 seeds tenant `…0001` with slug `default`, and the demo seed then renames
 * that slug to `demo`, so on a seeded install the literal matches neither the
 * id nor the slug.
 *
 * This asserts the two defaults agree, which is the part that will drift:
 * `next.config.js` is CommonJS and cannot import the constant.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_TENANT_ID } from '@/lib/api';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function nextConfigSource(): string {
  return readFileSync(path.join(process.cwd(), 'next.config.js'), 'utf8');
}

describe('the default tenant reference', () => {
  it('is a UUID, because every tenant-scoped route parses it as one', () => {
    expect(DEFAULT_TENANT_ID).toMatch(UUID);
  });

  it('is never the tenant slug', () => {
    // The slug the demo seed renames out from under any caller relying on it.
    expect(DEFAULT_TENANT_ID).not.toBe('default');
    expect(DEFAULT_TENANT_ID).not.toBe('demo');
  });

  it("matches next.config.js, which inlines the value and wins over api.ts", () => {
    const source = nextConfigSource();
    const match = source.match(/NEXT_PUBLIC_TENANT_ID:[\s\S]{0,200}?['"]([^'"]+)['"]/);

    expect(match, 'next.config.js no longer declares a NEXT_PUBLIC_TENANT_ID default').toBeTruthy();
    expect(match?.[1]).toBe(DEFAULT_TENANT_ID);
  });

  it('does not reintroduce a slug default anywhere in next.config.js', () => {
    expect(nextConfigSource()).not.toMatch(/NEXT_PUBLIC_TENANT_ID[\s\S]{0,120}?\|\|\s*['"]default['"]/);
  });
});
