/**
 * PWA helpers — service worker registration, install prompt capture,
 * Web Push subscription, and offline action queue glue.
 *
 * These are imported lazily by the client-only `<PwaBootstrap />` component
 * so the bundle stays out of the desktop console critical path.
 */

import { responderApi } from './api';

/** Convert a URL-safe base64 VAPID key into a Uint8Array. */
export function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = typeof atob === 'function'
    ? atob(base64)
    : Buffer.from(base64, 'base64').toString('binary');
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

export interface ServiceWorkerStatus {
  supported: boolean;
  registered: boolean;
  active: boolean;
  scope?: string;
  scriptUrl?: string;
}

/**
 * Register the AiSOC service worker. Safe to call multiple times — the
 * browser dedupes by `scriptUrl` + `scope`. Only runs in the browser.
 */
export async function registerServiceWorker(
  scriptUrl = '/sw.js',
  scope = '/',
): Promise<ServiceWorkerRegistration | null> {
  if (typeof window === 'undefined') return null;
  if (!('serviceWorker' in navigator)) return null;

  try {
    const reg = await navigator.serviceWorker.register(scriptUrl, {
      scope,
      // Auto-update once an hour while the tab is open. Beyond that the SW
      // self-updates on `controllerchange`.
      updateViaCache: 'none',
    });

    // Nudge an update check whenever the page becomes visible.
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
          reg.update().catch(() => {
            /* ignore — best-effort */
          });
        }
      });
    }

    return reg;
  } catch (err) {
    if (typeof console !== 'undefined') {
      console.warn('[pwa] service worker registration failed', err);
    }
    return null;
  }
}

export async function getServiceWorkerStatus(): Promise<ServiceWorkerStatus> {
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) {
    return { supported: false, registered: false, active: false };
  }
  const reg = await navigator.serviceWorker.getRegistration();
  if (!reg) return { supported: true, registered: false, active: false };
  return {
    supported: true,
    registered: true,
    active: !!reg.active,
    scope: reg.scope,
    scriptUrl: reg.active?.scriptURL,
  };
}

export interface PushPermissionResult {
  state: NotificationPermission;
  /** True when the browser supports both Notifications and Push. */
  supported: boolean;
}

/**
 * Ask the browser for notification permission, falling back gracefully on
 * iOS Safari (which only allows the prompt from a user gesture inside an
 * installed PWA).
 */
export async function requestNotificationPermission(): Promise<PushPermissionResult> {
  if (typeof window === 'undefined' || typeof Notification === 'undefined') {
    return { state: 'denied', supported: false };
  }
  if (!('PushManager' in window)) {
    return { state: 'denied', supported: false };
  }
  if (Notification.permission === 'granted') {
    return { state: 'granted', supported: true };
  }
  if (Notification.permission === 'denied') {
    return { state: 'denied', supported: true };
  }
  const state = await Notification.requestPermission();
  return { state, supported: true };
}

/**
 * Subscribe this device to Web Push and register the subscription with the
 * realtime gateway. Returns the active subscription on success.
 */
export async function subscribeToPush(
  options: { topics?: string[] } = {},
): Promise<PushSubscription | null> {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
    return null;
  }

  const reg = await navigator.serviceWorker.ready;
  if (!reg.pushManager) return null;

  const existing = await reg.pushManager.getSubscription();
  if (existing) {
    // Already subscribed; re-register with the gateway in case the
    // tenant context changed.
    await registerSubscriptionWithGateway(existing, options.topics);
    return existing;
  }

  const { public_key, enabled } = await responderApi.getPublicKey();
  if (!enabled || !public_key) {
    if (typeof console !== 'undefined') {
      console.info('[pwa] push disabled by server');
    }
    return null;
  }

  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(public_key),
  });

  await registerSubscriptionWithGateway(sub, options.topics);
  return sub;
}

async function registerSubscriptionWithGateway(
  sub: PushSubscription,
  topics?: string[],
): Promise<void> {
  const json = sub.toJSON();
  const keys = (json.keys ?? {}) as Record<string, string>;
  if (!json.endpoint || !keys.p256dh || !keys.auth) {
    throw new Error('Push subscription missing endpoint/keys');
  }
  await responderApi.subscribe({
    subscription: {
      endpoint: json.endpoint,
      keys: { p256dh: keys.p256dh, auth: keys.auth },
      expirationTime: json.expirationTime ?? null,
    },
    user_agent:
      typeof navigator !== 'undefined' ? navigator.userAgent : undefined,
    topics: topics ?? ['p0_alert', 'agent_approval', 'oncall_handoff'],
  });
}

export async function unsubscribeFromPush(): Promise<boolean> {
  if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
    return false;
  }
  const reg = await navigator.serviceWorker.getRegistration();
  if (!reg) return false;
  const sub = await reg.pushManager.getSubscription();
  if (!sub) return false;
  await responderApi.unsubscribe(sub.endpoint).catch(() => {});
  return await sub.unsubscribe();
}

/** Returns true when the page is loaded inside an installed PWA. */
export function isStandalone(): boolean {
  if (typeof window === 'undefined') return false;
  if (window.matchMedia?.('(display-mode: standalone)').matches) return true;
  // Safari iOS legacy flag.
  return Boolean(
    (window.navigator as Navigator & { standalone?: boolean }).standalone,
  );
}

export interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
}

let deferredInstallPrompt: BeforeInstallPromptEvent | null = null;
const installListeners = new Set<(available: boolean) => void>();

if (typeof window !== 'undefined') {
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e as BeforeInstallPromptEvent;
    installListeners.forEach((fn) => fn(true));
  });
  window.addEventListener('appinstalled', () => {
    deferredInstallPrompt = null;
    installListeners.forEach((fn) => fn(false));
  });
}

/** Subscribe to "install prompt available" changes. Returns an unsubscribe fn. */
export function onInstallPromptAvailable(
  fn: (available: boolean) => void,
): () => void {
  installListeners.add(fn);
  // Fire current state immediately.
  fn(deferredInstallPrompt !== null);
  return () => {
    installListeners.delete(fn);
  };
}

export async function showInstallPrompt(): Promise<'accepted' | 'dismissed' | 'unavailable'> {
  if (!deferredInstallPrompt) return 'unavailable';
  await deferredInstallPrompt.prompt();
  const { outcome } = await deferredInstallPrompt.userChoice;
  deferredInstallPrompt = null;
  installListeners.forEach((fn) => fn(false));
  return outcome;
}

// ─── Offline approval queue ───────────────────────────────────────────────
//
// When an on-call responder taps "approve" while offline, we stash the
// payload in IndexedDB and ask the SW to replay it via Background Sync. The
// SW reads the same store; this client-side helper writes into it.

const DB_NAME = 'aisoc-responder';
const DB_VERSION = 1;
const STORE_APPROVALS = 'pending-approvals';

async function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_APPROVALS)) {
        db.createObjectStore(STORE_APPROVALS, { keyPath: 'id' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export interface QueuedApproval {
  id: string;
  approval_id: string;
  decision: 'approve' | 'deny';
  comment?: string;
  reason?: string;
  queued_at: number;
}

export async function queueApproval(item: Omit<QueuedApproval, 'id' | 'queued_at'>): Promise<string> {
  if (typeof indexedDB === 'undefined') {
    throw new Error('IndexedDB not available');
  }
  const db = await openDb();
  const id = `${item.approval_id}:${Date.now()}`;
  const record: QueuedApproval = { ...item, id, queued_at: Date.now() };
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_APPROVALS, 'readwrite');
    tx.objectStore(STORE_APPROVALS).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });

  // Ask the SW to replay when connectivity returns.
  if ('serviceWorker' in navigator && 'SyncManager' in window) {
    const reg = await navigator.serviceWorker.ready;
    try {
      await (reg as ServiceWorkerRegistration & {
        sync?: { register: (tag: string) => Promise<void> };
      }).sync?.register('approval-replay');
    } catch {
      // Background Sync not available (e.g. Firefox) — the SW will replay
      // on the next `fetch` event instead.
    }
  }
  return id;
}

export async function listQueuedApprovals(): Promise<QueuedApproval[]> {
  if (typeof indexedDB === 'undefined') return [];
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_APPROVALS, 'readonly');
    const req = tx.objectStore(STORE_APPROVALS).getAll();
    req.onsuccess = () => resolve(req.result as QueuedApproval[]);
    req.onerror = () => reject(req.error);
  });
}
