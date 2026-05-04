/**
 * AiSOC Responder PWA service worker.
 *
 * Responsibilities:
 *  - App shell + static asset caching for offline-first access to /responder
 *  - Stale-while-revalidate for icons, fonts, and Next.js static chunks
 *  - Network-first for API calls with a graceful offline JSON fallback
 *  - Web Push notifications for "agent needs approval" / "P0 alert" / case updates
 *  - notificationclick handling that routes responders directly to the right view
 *
 * Versioning: bump CACHE_VERSION whenever the offline shell or routing strategy
 * changes — clients will discard old caches on activate.
 */

const CACHE_VERSION = 'v1.0.0';
const SHELL_CACHE = `aisoc-shell-${CACHE_VERSION}`;
const ASSET_CACHE = `aisoc-assets-${CACHE_VERSION}`;
const RUNTIME_CACHE = `aisoc-runtime-${CACHE_VERSION}`;

// Minimum app shell — must be cacheable so the responder can launch offline
// and at least see the last known triage state. /offline.html provides the
// graceful fallback when the network is unavailable for an uncached route.
const APP_SHELL = [
  '/responder',
  '/offline.html',
  '/manifest.json',
  '/favicon.svg',
  '/icons/icon-192.svg',
  '/icons/icon-512.svg',
  '/icons/icon-maskable.svg',
];

// ────────────────────────────────────────────────────────────────────────────
// Lifecycle
// ────────────────────────────────────────────────────────────────────────────

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
      .catch((err) => {
        // Best-effort: even if a single asset 404s during install, we still
        // want the SW to take over rather than fail to register.
        console.warn('[sw] shell precache partial failure', err);
        return self.skipWaiting();
      }),
  );
});

self.addEventListener('activate', (event) => {
  const allowed = new Set([SHELL_CACHE, ASSET_CACHE, RUNTIME_CACHE]);
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => !allowed.has(k)).map((k) => caches.delete(k))),
      )
      .then(() => self.clients.claim()),
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Fetch routing
// ────────────────────────────────────────────────────────────────────────────

self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Never intercept non-GET (POST approvals, mutations must always go to network)
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // Only handle same-origin requests; cross-origin (CDN/Auth) bypass to network.
  if (url.origin !== self.location.origin) return;

  // 1. API + realtime → network-first with offline JSON fallback.
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/sse') ||
    url.pathname.startsWith('/ws')
  ) {
    event.respondWith(networkFirst(request));
    return;
  }

  // 2. Next.js static chunks + Google fonts → stale-while-revalidate.
  if (url.pathname.startsWith('/_next/static/') || url.pathname.startsWith('/icons/')) {
    event.respondWith(staleWhileRevalidate(request, ASSET_CACHE));
    return;
  }

  // 3. HTML navigation → network-first with /offline.html fallback so the
  //    responder always sees *something* when on the train.
  if (request.mode === 'navigate') {
    event.respondWith(navigationStrategy(request));
    return;
  }

  // 4. Everything else → cache-first.
  event.respondWith(cacheFirst(request));
});

async function networkFirst(request) {
  try {
    const fresh = await fetch(request);
    // Cache successful API GETs so list views still render offline.
    if (fresh.ok) {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(request, fresh.clone());
    }
    return fresh;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    return new Response(
      JSON.stringify({
        offline: true,
        error: 'You are offline. Showing last cached state.',
      }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    );
  }
}

async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  const fetchPromise = fetch(request)
    .then((response) => {
      if (response.ok) cache.put(request, response.clone());
      return response;
    })
    .catch(() => cached);
  return cached || fetchPromise;
}

async function navigationStrategy(request) {
  try {
    const fresh = await fetch(request);
    return fresh;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    const offline = await caches.match('/offline.html');
    return (
      offline ||
      new Response('<h1>Offline</h1><p>AiSOC is offline.</p>', {
        status: 503,
        headers: { 'Content-Type': 'text/html' },
      })
    );
  }
}

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const fresh = await fetch(request);
    if (fresh.ok) {
      const cache = await caches.open(ASSET_CACHE);
      cache.put(request, fresh.clone());
    }
    return fresh;
  } catch (err) {
    return new Response('', { status: 504 });
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Web Push
// ────────────────────────────────────────────────────────────────────────────

self.addEventListener('push', (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (err) {
    payload = { title: 'AiSOC', body: event.data ? event.data.text() : 'New event' };
  }

  const {
    title = 'AiSOC',
    body = 'You have a new security event.',
    severity = 'info',
    icon = '/icons/icon-192.svg',
    badge = '/icons/icon-192.svg',
    tag,
    requireInteraction,
    data = {},
    actions = [],
  } = payload;

  // P0/P1 alerts and approval requests should require explicit dismissal so
  // the responder cannot accidentally swipe past a critical incident.
  const critical = severity === 'critical' || severity === 'high' || data.kind === 'approval_required';

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon,
      badge,
      tag: tag || data.tag || `aisoc-${Date.now()}`,
      requireInteraction: requireInteraction ?? critical,
      vibrate: critical ? [200, 100, 200, 100, 200] : [100, 50, 100],
      data,
      actions:
        actions.length > 0
          ? actions
          : data.kind === 'approval_required'
          ? [
              { action: 'approve', title: 'Approve' },
              { action: 'view', title: 'View case' },
            ]
          : [{ action: 'view', title: 'View' }],
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const action = event.action;

  // Build a deep-link URL from the payload so taps land on the exact view.
  let url = '/responder';
  if (data.case_id) url = `/responder/cases/${data.case_id}`;
  else if (data.alert_id) url = `/responder?alert=${data.alert_id}`;
  else if (data.run_id) url = `/responder/cases/${data.case_id || ''}?run=${data.run_id}`;

  if (action === 'approve' && data.approval_id) {
    url = `/responder/approve/${data.approval_id}`;
  }

  event.waitUntil(
    self.clients
      .matchAll({ type: 'window', includeUncontrolled: true })
      .then((clients) => {
        // Reuse an existing /responder window if open.
        for (const client of clients) {
          if (client.url.includes('/responder') && 'focus' in client) {
            client.navigate(url);
            return client.focus();
          }
        }
        if (self.clients.openWindow) return self.clients.openWindow(url);
      }),
  );
});

self.addEventListener('pushsubscriptionchange', (event) => {
  // Browser rotated subscription; re-register with the realtime service so
  // the responder keeps receiving pages without manual re-enrollment.
  event.waitUntil(
    (async () => {
      try {
        const sub = await self.registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: event.oldSubscription
            ? event.oldSubscription.options.applicationServerKey
            : undefined,
        });
        await fetch('/api/v1/push/subscribe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ subscription: sub.toJSON() }),
        });
      } catch (err) {
        console.warn('[sw] failed to refresh push subscription', err);
      }
    })(),
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Background sync (queued approvals when offline)
// ────────────────────────────────────────────────────────────────────────────

self.addEventListener('sync', (event) => {
  if (event.tag === 'aisoc-sync-approvals') {
    event.waitUntil(replayQueuedApprovals());
  }
});

async function replayQueuedApprovals() {
  // Approval mutations made while offline are stored in IndexedDB by the
  // /responder views; on reconnection we drain the queue here. The actual
  // queue impl lives in apps/web/src/lib/responder/offlineQueue.ts.
  const clients = await self.clients.matchAll();
  clients.forEach((c) => c.postMessage({ type: 'sync-approvals' }));
}

// Allow the page to skipWaiting and activate a new SW immediately.
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
