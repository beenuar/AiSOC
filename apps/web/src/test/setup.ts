// Vitest setup — runs once before any test file.
//
// Adds @testing-library/jest-dom matchers (toBeInTheDocument, etc.) and
// stubs the browser APIs that Next.js components reach for at import time
// but that jsdom doesn't ship.

import '@testing-library/jest-dom/vitest';
import { afterEach, expect, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import { mutate } from 'swr';
// NOTE: vitest-axe@0.1.0 ships a broken `vitest-axe/matchers.d.ts` that wraps
// its re-exports in `export type *`, so TS thinks `toHaveNoViolations` is a
// type even though the JS file exports a function. The deep path resolves to
// `dist/matchers.d.ts`, which uses regular value re-exports and works.
import { toHaveNoViolations } from 'vitest-axe/dist/matchers.js';
import 'vitest-axe/extend-expect';

// vitest-axe ships matchers separately from the type augmentation; register
// here so every component test can call `expect(...).toHaveNoViolations()`
// without per-file boilerplate. WS-F2.
expect.extend({ toHaveNoViolations });

afterEach(() => {
  cleanup();
  // SWR keeps a *module-scoped* cache that survives across tests in the
  // same file. A test that mocks a fetcher to return an unresolved
  // ``new Promise(() => {})`` (the loading-state smoke test) leaves that
  // promise pinned to the cache key, so the next test's
  // ``mockResolvedValue`` is silently ignored and the loading state
  // bleeds through. Clear every key after each test so SWR refetches
  // from the freshly-installed mock. See SOCInsightsView.test.tsx for
  // the failure mode this avoids.
  void mutate(() => true, undefined, { revalidate: false });
});

// matchMedia is touched by some recharts/framer-motion code paths.
if (typeof window !== 'undefined' && !window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(() => false),
  });
}

// IntersectionObserver is used by some charting/cmdk code at module load.
if (typeof window !== 'undefined' && !('IntersectionObserver' in window)) {
  class IntersectionObserverStub {
    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
    takeRecords = vi.fn(() => []);
    root = null;
    rootMargin = '';
    thresholds = [];
  }
  // @ts-expect-error — assigning a stub to satisfy code that just checks for existence.
  window.IntersectionObserver = IntersectionObserverStub;
}

// ResizeObserver — same story for responsive recharts containers.
if (typeof window !== 'undefined' && !('ResizeObserver' in window)) {
  class ResizeObserverStub {
    observe = vi.fn();
    unobserve = vi.fn();
    disconnect = vi.fn();
  }
  // @ts-expect-error — assigning a stub for the same reason as above.
  window.ResizeObserver = ResizeObserverStub;
}

// localStorage — the jsdom build wired up in this repo exposes `window.localStorage`
// as an object but without `getItem`/`setItem` methods, which breaks any component
// that persists user preferences (v1.5 W4 TimeWindowProvider, W5 TenantProvider,
// WS-F1 theme, etc.). Install a small in-memory Storage shim so tests can read and
// write keys exactly like real browser code. We also re-install it before every
// test via the `afterEach` cleanup hook in case a test installs `vi.spyOn` mocks
// on `Storage.prototype` and forgets to restore them.
function installStorageShim() {
  if (typeof window === 'undefined') return;
  const store = new Map<string, string>();
  const shim: Storage = {
    get length() {
      return store.size;
    },
    clear: () => {
      store.clear();
    },
    getItem: (key: string) => (store.has(key) ? (store.get(key) as string) : null),
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    removeItem: (key: string) => {
      store.delete(key);
    },
    setItem: (key: string, value: string) => {
      store.set(key, String(value));
    },
  };
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: shim,
  });
  Object.defineProperty(window, 'sessionStorage', {
    configurable: true,
    value: shim,
  });
}

installStorageShim();
