/**
 * Realtime WebSocket client for AiSOC.
 *
 * Wraps the `realtime` service (port 8086) with a small typed hook that
 * handles automatic reconnection, JSON parsing, and channel subscription.
 *
 * Usage:
 *
 *   const { last, send, status } = useRealtimeChannel<Alert>('alerts');
 *
 * The hook returns the latest decoded message plus a `send` callback for
 * outbound control frames (subscribe / unsubscribe / ping).
 */

'use client';

import { useEffect, useRef, useState } from 'react';
import { realtimeApi } from './api';

export type RealtimeChannel = 'alerts' | 'cases' | 'agents' | 'insights' | 'all';
export type RealtimeStatus =
  | 'connecting'
  | 'open'
  | 'closing'
  | 'closed'
  | 'error';

interface UseRealtimeOptions {
  /** When false the hook is a no-op — useful for SSR / disabled features. */
  enabled?: boolean;
  /** Override the URL (e.g. tests). Defaults to `realtimeApi.channelUrl`. */
  url?: string;
  /** Reconnect backoff cap in ms. */
  maxBackoffMs?: number;
}

interface UseRealtimeResult<T> {
  status: RealtimeStatus;
  last: T | null;
  history: T[];
  send: (message: unknown) => void;
  reset: () => void;
}

const DEFAULT_HISTORY = 50;

export function useRealtimeChannel<T = unknown>(
  channel: RealtimeChannel,
  options: UseRealtimeOptions = {},
): UseRealtimeResult<T> {
  const { enabled = true, url, maxBackoffMs = 15_000 } = options;
  const [status, setStatus] = useState<RealtimeStatus>('connecting');
  const [last, setLast] = useState<T | null>(null);
  const [history, setHistory] = useState<T[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<number>(0);
  const cancelRef = useRef(false);

  useEffect(() => {
    if (!enabled || typeof window === 'undefined') return;
    cancelRef.current = false;

    async function connect() {
      if (cancelRef.current) return;
      setStatus('connecting');

      // Mint a fresh short-lived ticket and attach it as `?token=` immediately
      // before opening the socket (Issue #239). On reconnect this re-mints, so
      // an expired ticket never blocks recovery. A test-supplied `url` override
      // bypasses ticketing.
      let target: string;
      try {
        target = url ?? (await realtimeApi.channelUrl(channel));
      } catch {
        // Could not authenticate (e.g. signed-out, or realtime ticketing is
        // not configured server-side → 503). Surface as error and retry with
        // backoff rather than opening an unauthenticated socket.
        if (cancelRef.current) return;
        setStatus('error');
        const attempt = reconnectRef.current + 1;
        reconnectRef.current = attempt;
        const delay = Math.min(1000 * 2 ** Math.min(attempt, 6), maxBackoffMs);
        window.setTimeout(connect, delay);
        return;
      }
      if (cancelRef.current) return;

      const ws = new WebSocket(target);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectRef.current = 0;
        setStatus('open');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as T;
          setLast(data);
          setHistory((prev) => {
            const next = [data, ...prev];
            return next.slice(0, DEFAULT_HISTORY);
          });
        } catch {
          // Non-JSON frames are silently dropped — surface as last-string?
        }
      };

      ws.onerror = () => setStatus('error');

      ws.onclose = () => {
        setStatus('closed');
        if (cancelRef.current) return;
        const attempt = reconnectRef.current + 1;
        reconnectRef.current = attempt;
        const delay = Math.min(1000 * 2 ** Math.min(attempt, 6), maxBackoffMs);
        window.setTimeout(connect, delay);
      };
    }

    connect();

    return () => {
      cancelRef.current = true;
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        setStatus('closing');
        ws.close();
      }
    };
  }, [channel, enabled, url, maxBackoffMs]);

  function send(message: unknown) {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(typeof message === 'string' ? message : JSON.stringify(message));
  }

  function reset() {
    setLast(null);
    setHistory([]);
  }

  return { status, last, history, send, reset };
}
