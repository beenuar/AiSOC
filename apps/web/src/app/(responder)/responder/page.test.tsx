import { afterEach, describe, expect, it, vi } from 'vitest';
import manifest from '../../../../public/manifest.json';

const redirectMock = vi.hoisted(() =>
  vi.fn((target: string): never => {
    throw new Error(`NEXT_REDIRECT:${target}`);
  }),
);

vi.mock('next/navigation', () => ({
  redirect: redirectMock,
}));

import ResponderIndexPage from './page';

afterEach(() => {
  redirectMock.mockClear();
});

async function visit(tab?: string | string[]) {
  // Next passes searchParams as a promise, including for requests with no tab.
  return ResponderIndexPage({ searchParams: Promise.resolve({ tab }) });
}

describe('installed Responder shortcuts', () => {
  it.each([
    { tab: 'queue', target: '/responder/triage' },
    { tab: 'cases', target: '/responder/case' },
    { tab: 'oncall', target: '/responder/oncall' },
  ])('routes the legacy $tab shortcut to $target', async ({ tab, target }) => {
    await expect(visit(tab)).rejects.toThrow(`NEXT_REDIRECT:${target}`);
    expect(redirectMock).toHaveBeenCalledExactlyOnceWith(target);
  });

  it.each([
    { label: 'missing', tab: undefined },
    { label: 'empty', tab: '' },
    { label: 'unknown', tab: 'unknown' },
    { label: 'a path', tab: '/responder/case' },
    { label: 'an external URL', tab: 'https://example.invalid/' },
    { label: 'an inherited object key', tab: 'constructor' },
    { label: 'a prototype key', tab: '__proto__' },
    { label: 'repeated conflicting values', tab: ['cases', 'oncall'] },
    { label: 'repeated identical values', tab: ['cases', 'cases'] },
  ])('defaults to triage when tab is $label', async ({ tab }) => {
    await expect(visit(tab)).rejects.toThrow('NEXT_REDIRECT:/responder/triage');
    expect(redirectMock).toHaveBeenCalledExactlyOnceWith('/responder/triage');
  });

  it.each([
    { name: 'Triage queue', target: '/responder/triage' },
    { name: 'My cases', target: '/responder/case' },
    { name: 'On-call status', target: '/responder/oncall' },
  ])('publishes the canonical $name shortcut', ({ name, target }) => {
    expect(manifest.shortcuts.find((shortcut) => shortcut.name === name)?.url).toBe(target);
  });
});
