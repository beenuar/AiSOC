// Vitest setup — runs once before any test file.
//
// Adds @testing-library/jest-dom matchers (toBeInTheDocument, etc.) and
// stubs the browser APIs that Next.js components reach for at import time
// but that jsdom doesn't ship.

import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

afterEach(() => {
  cleanup();
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
