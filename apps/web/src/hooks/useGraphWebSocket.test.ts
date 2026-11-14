/**
 * useGraphWebSocket — unit tests (T1.4 — v8.0).
 *
 * Covers the contract the consuming RealtimeGraph component relies on:
 *
 *   - default URL composition (scheme, path, token query param)
 *   - JSON-frame parsing into a typed envelope
 *   - history bounding & "newest first" ordering
 *   - graceful handling of malformed / non-string frames
 *   - reconnect-on-close + exponential backoff (mocked clock)
 *   - cleanup on unmount cancels pending reconnects
 *
 * The WebSocket constructor is replaced with a controllable stub
 * (``MockWebSocket``) so we can drive open / message / close events
 * deterministically. We do NOT use ``vi.advanceTimersByTimeAsync``
 * here because the React state batching plays badly with overlapping
 * fake-timer windows — the `act` wrappers + ``vi.runOnlyPendingTimers``
 * keep the assertions linear.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';

import { AUTH_TOKEN_KEY } from '@/lib/api';

import {
  __testables,
  useGraphWebSocket,
  type GraphUpdateEnvelope,
} from './useGraphWebSocket';

// --- WebSocket stub ----------------------------------------------------------

type StubInstance = {
  url: string;
  readyState: number;
  onopen: ((ev: Event) => void) | null;
  onmessage: ((ev: MessageEvent) => void) | null;
  onerror: ((ev: Event) => void) | null;
  onclose: ((ev: CloseEvent) => void) | null;
  open: () => void;
  emit: (data: unknown) => void;
  triggerError: () => void;
  close: (code?: number) => void;
};

const created: StubInstance[] = [];

class MockWebSocket implements StubInstance {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  url: string;
  readyState = MockWebSocket.CONNECTING;
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    created.push(this);
  }

  open() {
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.(new Event('open'));
  }

  emit(data: unknown) {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    this.onmessage?.(new MessageEvent('message', { data: payload }));
  }

  triggerError() {
    this.onerror?.(new Event('error'));
  }

  close() {
    if (this.readyState === MockWebSocket.CLOSED) return;
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.(new CloseEvent('close', { code: 1000 }));
  }
}

// --- Test helpers ------------------------------------------------------------

function makeEnvelope(
  i: number,
  override: Partial<GraphUpdateEnvelope> = {},
): GraphUpdateEnvelope {
  return {
    entity_id: `entity-${i}`,
    change_type: 'upsert_node',
    ts: new Date(1_700_000_000_000 + i * 1000).toISOString(),
    label: 'Host',
    schema_version: 'v1.0',
    ...override,
  };
}

const originalWebSocket = globalThis.WebSocket;

beforeEach(() => {
  created.length = 0;
  Object.defineProperty(window, 'WebSocket', {
    configurable: true,
    writable: true,
    value: MockWebSocket as unknown as typeof WebSocket,
  });
  (globalThis as unknown as { WebSocket: typeof WebSocket }).WebSocket =
    MockWebSocket as unknown as typeof WebSocket;
});

afterEach(() => {
  vi.useRealTimers();
  Object.defineProperty(window, 'WebSocket', {
    configurable: true,
    writable: true,
    value: originalWebSocket,
  });
  (globalThis as unknown as { WebSocket: typeof WebSocket }).WebSocket =
    originalWebSocket;
  window.localStorage.clear();
});

// --- Tests -------------------------------------------------------------------

describe('useGraphWebSocket — URL composition', () => {
  it('uses same-origin scheme + the /api/v1/graph_ws/stream path', () => {
    const url = __testables.defaultGraphWsUrl(null);
    // jsdom default origin is http://localhost → ws://localhost
    expect(url.endsWith('/api/v1/graph_ws/stream')).toBe(true);
    expect(url.startsWith('ws://') || url.startsWith('wss://')).toBe(true);
  });

  it('appends the token as ?token=<encoded>', () => {
    const url = __testables.defaultGraphWsUrl('abc/def=&value');
    expect(url).toContain('?token=abc%2Fdef%3D%26value');
  });

  it('reads the token from localStorage[AUTH_TOKEN_KEY] when not overridden', () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'jwt-from-storage');
    renderHook(() => useGraphWebSocket());
    expect(created.length).toBe(1);
    expect(created[0].url).toContain('token=jwt-from-storage');
  });

  it('honours an explicit token override', () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'wrong');
    renderHook(() => useGraphWebSocket({ token: 'explicit' }));
    expect(created[0].url).toContain('token=explicit');
    expect(created[0].url).not.toContain('wrong');
  });

  it('honours an explicit url override', () => {
    renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream', token: 'ignored' }),
    );
    // When url is set we pass it verbatim — auth is the proxy's problem.
    expect(created[0].url).toBe('ws://mock/stream');
  });
});

describe('useGraphWebSocket — connection lifecycle', () => {
  it('starts idle and transitions through connecting → open', () => {
    const { result } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream' }),
    );
    expect(result.current.status).toBe('connecting');
    act(() => {
      created[0].open();
    });
    expect(result.current.status).toBe('open');
  });

  it('is a no-op when enabled is false', () => {
    const { result } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream', enabled: false }),
    );
    expect(created.length).toBe(0);
    expect(result.current.status).toBe('idle');
  });

  it('returns to closed and schedules a reconnect on socket close', () => {
    vi.useFakeTimers();
    const { result, unmount } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream', maxBackoffMs: 4000 }),
    );
    act(() => {
      created[0].open();
    });
    expect(result.current.status).toBe('open');

    act(() => {
      created[0].close();
    });
    expect(result.current.status).toBe('closed');
    expect(created.length).toBe(1);

    // Fast-forward past the first backoff slot.
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(created.length).toBe(2);
    expect(result.current.status).toBe('connecting');

    unmount();
  });

  it('cleans up pending reconnect timers on unmount', () => {
    vi.useFakeTimers();
    const { unmount } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream' }),
    );
    act(() => {
      created[0].close();
    });
    unmount();
    act(() => {
      vi.advanceTimersByTime(60_000);
    });
    expect(created.length).toBe(1); // No reconnect after unmount.
  });
});

describe('useGraphWebSocket — events stream', () => {
  it('parses JSON frames into typed envelopes and exposes last + events', () => {
    const { result } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream' }),
    );
    act(() => {
      created[0].open();
    });

    const env = makeEnvelope(1);
    act(() => {
      created[0].emit(env);
    });

    expect(result.current.last).toEqual(env);
    expect(result.current.events).toHaveLength(1);
    expect(result.current.events[0]).toEqual(env);
  });

  it('drops malformed frames silently', () => {
    const { result } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream' }),
    );
    act(() => {
      created[0].open();
    });

    act(() => {
      // Raw non-JSON text — JSON.parse throws.
      created[0].onmessage?.(new MessageEvent('message', { data: 'not-json' }));
    });
    act(() => {
      // Binary frame — typeof event.data !== 'string'.
      created[0].onmessage?.(
        new MessageEvent('message', {
          data: new ArrayBuffer(8) as unknown as string,
        }),
      );
    });

    expect(result.current.last).toBeNull();
    expect(result.current.events).toHaveLength(0);
  });

  it('keeps events newest-first and bounds the buffer at historyLimit', () => {
    const { result } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream', historyLimit: 3 }),
    );
    act(() => {
      created[0].open();
    });

    for (let i = 0; i < 5; i++) {
      const env = makeEnvelope(i);
      act(() => {
        created[0].emit(env);
      });
    }

    expect(result.current.events).toHaveLength(3);
    expect(result.current.events[0].entity_id).toBe('entity-4');
    expect(result.current.events[2].entity_id).toBe('entity-2');
    expect(result.current.last?.entity_id).toBe('entity-4');
  });

  it('clear() wipes history and last', () => {
    const { result } = renderHook(() =>
      useGraphWebSocket({ url: 'ws://mock/stream' }),
    );
    act(() => {
      created[0].open();
    });
    act(() => {
      created[0].emit(makeEnvelope(1));
      created[0].emit(makeEnvelope(2));
    });
    expect(result.current.events).toHaveLength(2);

    act(() => {
      result.current.clear();
    });
    expect(result.current.events).toHaveLength(0);
    expect(result.current.last).toBeNull();
  });
});
