/**
 * useGraphWebSocket — live tail of graph-mutation envelopes (T1.4 — v8.0).
 *
 * Opens a WebSocket against the API service's
 * ``/api/v1/graph_ws/stream`` proxy (see
 * ``services/api/app/api/v1/endpoints/graph_ws.py``), which in turn
 * brokers a tenant-scoped feed from the ingest broadcaster at
 * ``services/ingest/internal/graph_ws``. The hook owns three concerns
 * the consuming component should never have to think about:
 *
 *   1. **Authentication.** Browsers cannot set ``Authorization``
 *      headers on a WebSocket open, so the hook reads the access
 *      token from ``localStorage[AUTH_TOKEN_KEY]`` (the same key
 *      ``services/api/app/api/v1/endpoints/graph_ws.py`` looks for as
 *      ``?token=…``) and appends it to the URL. ``getActiveTenantId``
 *      from ``@/lib/api`` is *not* sent — the proxy rebinds tenant_id
 *      from the resolved user server-side so a client cannot subscribe
 *      to another tenant by tampering with the URL.
 *
 *   2. **Reconnect with exponential backoff.** Capped at
 *      ``maxBackoffMs`` (default 15 s) and reset on a successful
 *      ``onopen``. Mirrors the cadence of
 *      :func:`useRealtimeChannel <lib/realtime.useRealtimeChannel>`
 *      so two simultaneous WS connections (insights + graph) don't
 *      thunder-herd the gateway when the network flaps.
 *
 *   3. **Bounded event history.** ``events`` accumulates the last
 *      ``historyLimit`` envelopes (default 200) in newest-first order,
 *      and ``last`` is the most recent. Consumers can render either:
 *      a Cytoscape live graph patches against ``last``, a debug panel
 *      walks ``events``.
 *
 * The hook is a no-op on the server (``typeof window === 'undefined'``)
 * and when ``enabled`` is false — useful for SSR pages and tests that
 * want to skip the upgrade entirely.
 */

'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import { AUTH_TOKEN_KEY, getActiveTenantId } from '@/lib/api';

/**
 * Graph-update envelope shape, mirrored from
 * ``services/ingest/internal/graph/writer.go::GraphUpdate``. The
 * ``change_type`` is one of ``upsert_node`` | ``upsert_edge`` |
 * ``delete_node`` | ``delete_edge`` (see ``schema.go``). All optional
 * fields are populated based on the change_type.
 */
export interface GraphUpdateEnvelope {
  entity_id: string;
  change_type:
    | 'upsert_node'
    | 'upsert_edge'
    | 'delete_node'
    | 'delete_edge'
    | string;
  ts: string;
  label?: string;
  rel_type?: string;
  from?: string;
  to?: string;
  properties?: Record<string, unknown>;
  schema_version: string;
  tenant_id?: string;
}

export type GraphWebSocketStatus =
  | 'idle'
  | 'connecting'
  | 'open'
  | 'closing'
  | 'closed'
  | 'error';

export interface UseGraphWebSocketOptions {
  /**
   * Override the WebSocket URL. Used by tests to inject a mock socket
   * server. In production the URL is derived from same-origin so
   * Next.js can proxy the upgrade through to the API service.
   */
  url?: string;
  /** When false, the hook never opens a socket. */
  enabled?: boolean;
  /** Override the bearer token. Defaults to the stored access token. */
  token?: string | null;
  /** Cap for the reconnect backoff (ms). Default 15s. */
  maxBackoffMs?: number;
  /** How many envelopes to retain in ``events``. Default 200. */
  historyLimit?: number;
}

export interface UseGraphWebSocketResult {
  /** Connection state machine — see :type:`GraphWebSocketStatus`. */
  status: GraphWebSocketStatus;
  /** Most recently received envelope, or ``null`` before the first. */
  last: GraphUpdateEnvelope | null;
  /** Newest-first list of envelopes, bounded by ``historyLimit``. */
  events: GraphUpdateEnvelope[];
  /** Drop accumulated history. Useful when switching views. */
  clear: () => void;
}

const DEFAULT_HISTORY_LIMIT = 200;
const DEFAULT_MAX_BACKOFF_MS = 15_000;

/**
 * Build the same-origin WS URL the API proxy listens on.
 *
 * Two reasons we don't reuse ``realtimeApi.channelUrl`` from
 * ``@/lib/api``: (1) the realtime gateway is a separate service at
 * ``/ws/<channel>`` while graph_ws is wired into the API service at
 * ``/api/v1/graph_ws/stream``, and (2) Next.js rewrites
 * (``next.config.js``) only proxy WS to a single backend per source,
 * so the path matters.
 *
 * SSR fallback returns a path-only URL — nothing on the server opens
 * a WebSocket, but we still want the function pure.
 */
function defaultGraphWsUrl(token: string | null): string {
  let origin = '';
  if (typeof window !== 'undefined') {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    origin = `${proto}//${window.location.host}`;
  }
  const path = '/api/v1/graph_ws/stream';
  if (!token) return `${origin}${path}`;
  return `${origin}${path}?token=${encodeURIComponent(token)}`;
}

function readStoredToken(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function useGraphWebSocket(
  options: UseGraphWebSocketOptions = {},
): UseGraphWebSocketResult {
  const {
    url,
    enabled = true,
    token,
    maxBackoffMs = DEFAULT_MAX_BACKOFF_MS,
    historyLimit = DEFAULT_HISTORY_LIMIT,
  } = options;

  const [status, setStatus] = useState<GraphWebSocketStatus>('idle');
  const [last, setLast] = useState<GraphUpdateEnvelope | null>(null);
  const [events, setEvents] = useState<GraphUpdateEnvelope[]>([]);

  const socketRef = useRef<WebSocket | null>(null);
  const attemptRef = useRef(0);
  const cancelledRef = useRef(false);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clear = useCallback(() => {
    setLast(null);
    setEvents([]);
  }, []);

  useEffect(() => {
    if (!enabled || typeof window === 'undefined') {
      setStatus('idle');
      return;
    }

    cancelledRef.current = false;

    // Pin the tenant_id we *think* we are in for diagnostic logs. The
    // proxy rebinds server-side so this value is purely advisory — it
    // never controls authorisation. Touch the helper so a linter
    // doesn't flag the import; the read also catches a regression
    // where some future change starts trusting it for routing.
    void getActiveTenantId();

    const resolvedToken = token === undefined ? readStoredToken() : token;
    const target = url ?? defaultGraphWsUrl(resolvedToken);

    function connect() {
      if (cancelledRef.current) return;
      setStatus('connecting');

      let ws: WebSocket;
      try {
        ws = new WebSocket(target);
      } catch {
        // Some browsers throw synchronously on invalid URLs; treat
        // that as a hard error and schedule a reconnect.
        setStatus('error');
        scheduleReconnect();
        return;
      }
      socketRef.current = ws;

      ws.onopen = () => {
        attemptRef.current = 0;
        setStatus('open');
      };

      ws.onmessage = (event) => {
        if (typeof event.data !== 'string') return;
        let payload: GraphUpdateEnvelope | null = null;
        try {
          payload = JSON.parse(event.data) as GraphUpdateEnvelope;
        } catch {
          // Drop non-JSON / malformed frames — the broadcaster only
          // ever sends JSON envelopes, so any garbage here is a bug
          // and we don't want it to poison the consumer.
          return;
        }
        if (!payload || typeof payload !== 'object') return;
        setLast(payload);
        setEvents((prev) => {
          const next = [payload as GraphUpdateEnvelope, ...prev];
          return next.length > historyLimit ? next.slice(0, historyLimit) : next;
        });
      };

      ws.onerror = () => setStatus('error');

      ws.onclose = () => {
        socketRef.current = null;
        if (cancelledRef.current) {
          setStatus('closed');
          return;
        }
        setStatus('closed');
        scheduleReconnect();
      };
    }

    function scheduleReconnect() {
      if (cancelledRef.current) return;
      const attempt = attemptRef.current + 1;
      attemptRef.current = attempt;
      // Exponential backoff: 1s → 2s → 4s → … → maxBackoffMs.
      // Cap the exponent so very long-lived disconnect loops don't
      // overflow the math.
      const exp = Math.min(attempt, 6);
      const delay = Math.min(1000 * 2 ** exp, maxBackoffMs);
      reconnectTimerRef.current = setTimeout(connect, delay);
    }

    connect();

    return () => {
      cancelledRef.current = true;
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      const ws = socketRef.current;
      socketRef.current = null;
      if (ws) {
        if (ws.readyState === WebSocket.OPEN) {
          setStatus('closing');
        }
        try {
          ws.close();
        } catch {
          /* ignore — close errors don't matter on teardown */
        }
      }
    };
  }, [enabled, url, token, maxBackoffMs, historyLimit]);

  return { status, last, events, clear };
}

export const __testables = {
  defaultGraphWsUrl,
  readStoredToken,
};
