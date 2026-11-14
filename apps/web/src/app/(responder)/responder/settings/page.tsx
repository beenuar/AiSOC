'use client';

/**
 * Mobile responder settings.
 *
 * The single most important job of this page is to give the on-call a real
 * affordance for *enabling Web Push*. Browsers refuse to prompt for
 * notification permission outside a user gesture, and iOS Safari refuses
 * to prompt at all unless the page is running inside an installed PWA, so
 * this page also surfaces "Add to Home Screen" and clear diagnostics when
 * something blocks the happy path.
 *
 * Everything else is grouped by mental model: identity, alerts, devices.
 *
 *   1. Account            — who you're signed in as + sign out
 *   2. Notifications      — push permission, subscribe / unsubscribe, test
 *   3. Install            — A2HS prompt + standalone status
 *   4. Passkeys           — enroll on this device, list, revoke
 *   5. Diagnostics        — SW status, build info (collapsed by default)
 */

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import {
  passkeyApi,
  responderApi,
  type PasskeyCredential,
} from '@/lib/api';
import {
  clearSession,
  getProfile,
  type ResponderProfile,
} from '@/lib/responder/auth';
import { formatRelative } from '@/lib/responder/format';
import {
  createPasskey,
  isWebAuthnSupported,
} from '@/lib/responder/webauthn';
import {
  getServiceWorkerStatus,
  isStandalone,
  onInstallPromptAvailable,
  requestNotificationPermission,
  showInstallPrompt,
  subscribeToPush,
  type ServiceWorkerStatus,
  unsubscribeFromPush,
} from '@/lib/pwa';

type PushState = 'unsupported' | 'denied' | 'idle' | 'granted-unsubscribed' | 'subscribed';

const ALL_TOPICS: { id: string; label: string; help: string }[] = [
  {
    id: 'p0_alert',
    label: 'P0 alerts',
    help: 'Highest-severity detections that need eyes on glass now.',
  },
  {
    id: 'agent_approval',
    label: 'Agent approvals',
    help: 'Containment actions waiting for your sign-off.',
  },
  {
    id: 'oncall_handoff',
    label: 'On-call handoff',
    help: 'Rotation flips, page-overs, and "you are now on-call" pings.',
  },
];

const TOPIC_PREF_KEY = 'aisoc.responder.push.topics';

function loadTopicPrefs(): Set<string> {
  if (typeof window === 'undefined') {
    return new Set(ALL_TOPICS.map((t) => t.id));
  }
  try {
    const raw = window.localStorage.getItem(TOPIC_PREF_KEY);
    if (!raw) return new Set(ALL_TOPICS.map((t) => t.id));
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return new Set(parsed.filter((x) => typeof x === 'string'));
  } catch {
    /* fall through */
  }
  return new Set(ALL_TOPICS.map((t) => t.id));
}

function saveTopicPrefs(topics: Set<string>): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(
      TOPIC_PREF_KEY,
      JSON.stringify(Array.from(topics)),
    );
  } catch {
    /* private mode — silent. */
  }
}

export default function ResponderSettingsPage() {
  const router = useRouter();
  const [profile, setProfile] = useState<ResponderProfile | null>(null);
  const [pushState, setPushState] = useState<PushState>('idle');
  const [pushBusy, setPushBusy] = useState<boolean>(false);
  const [topics, setTopics] = useState<Set<string>>(() => new Set());
  const [installAvailable, setInstallAvailable] = useState(false);
  const [standalone, setStandalone] = useState(false);
  const [swStatus, setSwStatus] = useState<ServiceWorkerStatus | null>(null);
  const [credentials, setCredentials] = useState<PasskeyCredential[] | null>(
    null,
  );
  const [credentialsError, setCredentialsError] = useState<string | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const webauthnSupported = useMemo(() => isWebAuthnSupported(), []);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(null), 2400);
  }, []);

  // Resolve the current push state from browser APIs + active subscription.
  const refreshPushState = useCallback(async () => {
    if (
      typeof window === 'undefined' ||
      typeof Notification === 'undefined' ||
      !('serviceWorker' in navigator) ||
      !('PushManager' in window)
    ) {
      setPushState('unsupported');
      return;
    }
    if (Notification.permission === 'denied') {
      setPushState('denied');
      return;
    }
    if (Notification.permission !== 'granted') {
      setPushState('idle');
      return;
    }
    try {
      const reg = await navigator.serviceWorker.getRegistration();
      const sub = await reg?.pushManager.getSubscription();
      setPushState(sub ? 'subscribed' : 'granted-unsubscribed');
    } catch {
      setPushState('granted-unsubscribed');
    }
  }, []);

  // Load on mount: identity, push state, install state, SW status, passkeys.
  useEffect(() => {
    setProfile(getProfile());
    setTopics(loadTopicPrefs());
    setStandalone(isStandalone());
    void refreshPushState();
    void getServiceWorkerStatus().then(setSwStatus);

    const dispose = onInstallPromptAvailable(setInstallAvailable);
    return dispose;
  }, [refreshPushState]);

  // Passkey list — fail soft so the rest of the page still works if the API
  // is degraded.
  const loadCredentials = useCallback(async () => {
    setCredentialsError(null);
    try {
      const res = await passkeyApi.list();
      setCredentials(res.items ?? []);
    } catch (err) {
      console.error('[responder] failed to list passkeys', err);
      setCredentials([]);
      setCredentialsError(
        err instanceof Error ? err.message : 'Failed to load passkeys.',
      );
    }
  }, []);

  useEffect(() => {
    void loadCredentials();
  }, [loadCredentials]);

  // ─── Notifications ──────────────────────────────────────────────────────

  const enableNotifications = useCallback(async () => {
    setPushBusy(true);
    try {
      const permission = await requestNotificationPermission();
      if (!permission.supported) {
        showToast('Push not supported in this browser.');
        setPushState('unsupported');
        return;
      }
      if (permission.state === 'denied') {
        showToast('Permission denied. Enable in browser settings.');
        setPushState('denied');
        return;
      }
      if (permission.state !== 'granted') {
        // The user dismissed the prompt without choosing.
        setPushState('idle');
        return;
      }
      const sub = await subscribeToPush({ topics: Array.from(topics) });
      if (sub) {
        setPushState('subscribed');
        showToast('Notifications enabled.');
      } else {
        showToast('Push disabled by server.');
        setPushState('granted-unsubscribed');
      }
    } catch (err) {
      console.error('[responder] enable push failed', err);
      showToast(err instanceof Error ? err.message : 'Failed to enable push.');
      await refreshPushState();
    } finally {
      setPushBusy(false);
    }
  }, [refreshPushState, showToast, topics]);

  const disableNotifications = useCallback(async () => {
    setPushBusy(true);
    try {
      await unsubscribeFromPush();
      setPushState('granted-unsubscribed');
      showToast('Notifications disabled on this device.');
    } catch (err) {
      console.error('[responder] disable push failed', err);
      showToast(err instanceof Error ? err.message : 'Failed to disable push.');
    } finally {
      setPushBusy(false);
    }
  }, [showToast]);

  const sendTestPush = useCallback(async () => {
    setPushBusy(true);
    try {
      const res = await responderApi.testNotify();
      const sent = res?.sent ?? 0;
      showToast(
        sent > 0
          ? `Test sent to ${sent} device${sent === 1 ? '' : 's'}.`
          : 'No active subscriptions yet.',
      );
    } catch (err) {
      console.error('[responder] test push failed', err);
      showToast(err instanceof Error ? err.message : 'Test failed.');
    } finally {
      setPushBusy(false);
    }
  }, [showToast]);

  const toggleTopic = useCallback(
    async (topicId: string) => {
      const next = new Set(topics);
      if (next.has(topicId)) next.delete(topicId);
      else next.add(topicId);
      setTopics(next);
      saveTopicPrefs(next);

      // If we're already subscribed, re-register with the gateway so the
      // updated topic list takes effect on the next push. We don't show a
      // toast for every toggle — that would be noisy — but errors still pop.
      if (pushState === 'subscribed') {
        try {
          await subscribeToPush({ topics: Array.from(next) });
        } catch (err) {
          console.error('[responder] topic resubscribe failed', err);
          showToast('Couldn’t update topic preferences.');
        }
      }
    },
    [pushState, showToast, topics],
  );

  // ─── Install ────────────────────────────────────────────────────────────

  const handleInstall = useCallback(async () => {
    const outcome = await showInstallPrompt();
    if (outcome === 'accepted') {
      showToast('Installed. Look for the AiSOC icon on your home screen.');
      setStandalone(true);
    } else if (outcome === 'dismissed') {
      showToast('Install cancelled.');
    } else {
      showToast('Install prompt unavailable.');
    }
  }, [showToast]);

  // ─── Passkeys ───────────────────────────────────────────────────────────

  const handleEnrollPasskey = useCallback(async () => {
    if (!webauthnSupported) {
      showToast('This browser doesn’t support passkeys.');
      return;
    }
    setEnrolling(true);
    try {
      const ua =
        typeof navigator !== 'undefined' && navigator.userAgent
          ? navigator.userAgent.split(' ').slice(-1)[0] // crude device hint
          : 'Mobile';
      const begin = await passkeyApi.registerBegin(`${ua} – PWA`);
      const credential = await createPasskey(
        begin.publicKey as unknown as Parameters<typeof createPasskey>[0],
      );
      await passkeyApi.registerFinish(
        begin.challenge,
        credential as unknown as Record<string, unknown>,
      );
      showToast('Passkey enrolled on this device.');
      void loadCredentials();
    } catch (err) {
      console.error('[responder] passkey enroll failed', err);
      if (
        err instanceof DOMException &&
        (err.name === 'NotAllowedError' || err.name === 'AbortError')
      ) {
        showToast('Cancelled.');
      } else {
        showToast(
          err instanceof Error ? err.message : 'Passkey enrollment failed.',
        );
      }
    } finally {
      setEnrolling(false);
    }
  }, [loadCredentials, showToast, webauthnSupported]);

  const handleRevokePasskey = useCallback(
    async (id: string) => {
      setRevokingId(id);
      try {
        await passkeyApi.delete(id);
        setCredentials((prev) => (prev ?? []).filter((c) => c.id !== id));
        showToast('Passkey revoked.');
      } catch (err) {
        console.error('[responder] passkey revoke failed', err);
        showToast(err instanceof Error ? err.message : 'Revoke failed.');
      } finally {
        setRevokingId(null);
      }
    },
    [showToast],
  );

  // ─── Sign out ───────────────────────────────────────────────────────────

  const handleSignOut = useCallback(() => {
    void unsubscribeFromPush().catch(() => undefined);
    clearSession();
    router.replace('/responder/login');
  }, [router]);

  // ─── Render ─────────────────────────────────────────────────────────────

  return (
    <div className="px-4 pt-4 pb-2">
      <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
      <p className="text-xs text-zinc-500 mt-0.5">
        Notifications, install, and passkeys for this device.
      </p>

      {/* ── Account ──────────────────────────────────────────────────── */}
      <Section
        title="Account"
        description="The person paged when alerts route to you."
      >
        <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/50 px-4 py-3">
          <div className="text-xs uppercase tracking-wider text-zinc-500">
            Signed in as
          </div>
          <div className="text-sm font-medium text-zinc-100 truncate">
            {profile?.name ?? profile?.email ?? '—'}
          </div>
          {profile?.email ? (
            <div className="text-[11px] text-zinc-500 truncate mt-0.5">
              {profile.email}
            </div>
          ) : null}
        </div>
      </Section>

      {/* ── Notifications ────────────────────────────────────────────── */}
      <Section
        title="Notifications"
        description={
          pushState === 'unsupported'
            ? 'Your browser doesn’t support Web Push.'
            : pushState === 'denied'
              ? 'Permission was denied. Re-enable in your browser settings.'
              : pushState === 'subscribed'
                ? 'You’ll get pushes for the topics below — even when this tab is closed.'
                : 'Tap to enable pushes for P0 alerts and approvals.'
        }
      >
        <div className="space-y-3">
          <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/50 px-4 py-3">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-sm font-medium text-zinc-100">
                  Push notifications
                </div>
                <div className="mt-0.5">
                  <PushStatusPill state={pushState} />
                </div>
              </div>
              {pushState === 'subscribed' ? (
                <button
                  type="button"
                  onClick={() => void disableNotifications()}
                  disabled={pushBusy}
                  className="px-3 py-2 text-xs font-medium rounded-lg border border-zinc-700 hover:border-zinc-500 text-zinc-300 hover:text-zinc-100 transition disabled:opacity-60"
                >
                  Disable
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => void enableNotifications()}
                  disabled={
                    pushBusy ||
                    pushState === 'unsupported' ||
                    pushState === 'denied'
                  }
                  className="px-3 py-2 text-xs font-medium rounded-lg bg-indigo-500 hover:bg-indigo-400 active:bg-indigo-600 text-white transition disabled:bg-zinc-800 disabled:text-zinc-500"
                >
                  {pushBusy ? '…' : 'Enable'}
                </button>
              )}
            </div>
          </div>

          {/* Topic preferences — visible when push is supported, even before
              subscribe, so users can pre-pick what they want. */}
          {pushState !== 'unsupported' ? (
            <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/30">
              <div className="px-4 py-2.5 border-b border-zinc-800/80">
                <div className="text-xs uppercase tracking-wider text-zinc-500">
                  What to push
                </div>
              </div>
              <ul className="divide-y divide-zinc-800/80">
                {ALL_TOPICS.map((t) => {
                  const enabled = topics.has(t.id);
                  return (
                    <li key={t.id} className="px-4 py-3 flex items-start gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="text-sm text-zinc-100">{t.label}</div>
                        <div className="text-[11px] text-zinc-500 mt-0.5 leading-snug">
                          {t.help}
                        </div>
                      </div>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={enabled}
                        aria-label={`Toggle ${t.label}`}
                        onClick={() => void toggleTopic(t.id)}
                        className={clsx(
                          'shrink-0 w-11 h-6 rounded-full relative transition',
                          enabled ? 'bg-indigo-500' : 'bg-zinc-700',
                        )}
                      >
                        <span
                          className={clsx(
                            'absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform',
                            enabled ? 'translate-x-5' : 'translate-x-0.5',
                          )}
                        />
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : null}

          {pushState === 'subscribed' ? (
            <button
              type="button"
              onClick={() => void sendTestPush()}
              disabled={pushBusy}
              className="w-full px-3 py-2.5 text-sm font-medium rounded-lg bg-zinc-900/50 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-200 transition disabled:opacity-60"
            >
              Send test notification
            </button>
          ) : null}
        </div>
      </Section>

      {/* ── Install ──────────────────────────────────────────────────── */}
      <Section
        title="Install"
        description={
          standalone
            ? 'Running as an installed PWA. Pushes will deliver even when the browser is closed.'
            : 'Add AiSOC to your home screen for full-screen access and faster cold-starts.'
        }
      >
        <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/50 px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <div className="text-sm font-medium text-zinc-100">
                Add to home screen
              </div>
              <div className="text-[11px] text-zinc-500 mt-0.5 leading-snug">
                {standalone
                  ? 'Already installed.'
                  : installAvailable
                    ? 'Tap install to drop the AiSOC icon on your home screen.'
                    : 'Use your browser’s “Add to Home Screen” menu (Safari: Share → Add to Home Screen).'}
              </div>
            </div>
            {standalone ? (
              <span className="shrink-0 text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border bg-emerald-500/15 text-emerald-300 border-emerald-500/30">
                Installed
              </span>
            ) : (
              <button
                type="button"
                onClick={() => void handleInstall()}
                disabled={!installAvailable}
                className="px-3 py-2 text-xs font-medium rounded-lg bg-indigo-500 hover:bg-indigo-400 active:bg-indigo-600 text-white transition disabled:bg-zinc-800 disabled:text-zinc-500"
              >
                Install
              </button>
            )}
          </div>
        </div>
      </Section>

      {/* ── Passkeys ─────────────────────────────────────────────────── */}
      <Section
        title="Passkeys"
        description="Each passkey is bound to one device. Revoke any you don’t recognize."
      >
        {credentialsError ? (
          <div className="rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-xs text-red-300 mb-3">
            {credentialsError}
          </div>
        ) : null}

        {credentials === null ? (
          <SkeletonList />
        ) : credentials.length === 0 ? (
          <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/30 px-4 py-6 text-center">
            <p className="text-sm text-zinc-300">No passkeys enrolled yet.</p>
            <p className="text-[11px] text-zinc-500 mt-1">
              Enrolling here means this device — phone, fingerprint, Face ID —
              becomes your sign-in.
            </p>
          </div>
        ) : (
          <ul className="rounded-xl border border-zinc-800/80 bg-zinc-900/30 divide-y divide-zinc-800/80 overflow-hidden">
            {credentials.map((c) => (
              <li
                key={c.id}
                className="px-4 py-3 flex items-center gap-3"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-zinc-100 truncate">
                    {c.device_name || 'Unnamed device'}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-[11px] text-zinc-500">
                    <span>added {formatRelative(c.created_at)}</span>
                    {c.last_used_at ? (
                      <>
                        <span aria-hidden>·</span>
                        <span>used {formatRelative(c.last_used_at)}</span>
                      </>
                    ) : (
                      <>
                        <span aria-hidden>·</span>
                        <span>never used</span>
                      </>
                    )}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => void handleRevokePasskey(c.id)}
                  disabled={revokingId === c.id}
                  className="px-2 py-1.5 text-[11px] uppercase tracking-wider rounded-md border border-red-500/40 text-red-300 hover:bg-red-500/10 transition disabled:opacity-60"
                >
                  {revokingId === c.id ? '…' : 'Revoke'}
                </button>
              </li>
            ))}
          </ul>
        )}

        <button
          type="button"
          onClick={() => void handleEnrollPasskey()}
          disabled={!webauthnSupported || enrolling}
          className="mt-3 w-full px-3 py-3 text-sm font-medium rounded-lg bg-indigo-500 hover:bg-indigo-400 active:bg-indigo-600 text-white transition flex items-center justify-center gap-2 disabled:bg-zinc-800 disabled:text-zinc-500"
        >
          {enrolling ? (
            <>
              <svg
                className="w-4 h-4 animate-spin"
                fill="none"
                viewBox="0 0 24 24"
                aria-hidden
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="3"
                />
                <path
                  className="opacity-90"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                />
              </svg>
              <span>Waiting for passkey…</span>
            </>
          ) : (
            <span>Enroll passkey on this device</span>
          )}
        </button>

        {!webauthnSupported ? (
          <p className="mt-2 text-[11px] text-amber-300/90 leading-snug">
            Passkeys aren’t supported in this browser. Use Safari on iOS or
            Chrome on Android.
          </p>
        ) : null}
      </Section>

      {/* ── Diagnostics ──────────────────────────────────────────────── */}
      <Section title="Diagnostics" collapsed onToggle={() => setShowDiagnostics((v) => !v)} expanded={showDiagnostics}>
        {showDiagnostics ? (
          <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/30 px-4 py-3 space-y-2">
            <DiagRow
              label="Service worker"
              value={
                swStatus
                  ? !swStatus.supported
                    ? 'unsupported'
                    : swStatus.active
                      ? `active${swStatus.scope ? ` · ${swStatus.scope}` : ''}`
                      : swStatus.registered
                        ? 'registered, not yet active'
                        : 'not registered'
                  : 'checking…'
              }
            />
            <DiagRow
              label="Notification permission"
              value={
                typeof Notification !== 'undefined'
                  ? Notification.permission
                  : 'unsupported'
              }
            />
            <DiagRow label="Push state" value={pushState} />
            <DiagRow
              label="Display mode"
              value={standalone ? 'standalone (PWA)' : 'browser tab'}
            />
            <DiagRow
              label="User agent"
              value={
                typeof navigator !== 'undefined'
                  ? navigator.userAgent
                  : 'unknown'
              }
              mono
            />
          </div>
        ) : null}
      </Section>

      {/* ── Footer / sign out ────────────────────────────────────────── */}
      <div className="mt-6 pt-4 border-t border-zinc-900">
        <button
          type="button"
          onClick={handleSignOut}
          className="w-full px-3 py-3 text-sm font-medium rounded-lg border border-zinc-800 hover:border-red-500/50 text-zinc-300 hover:text-red-300 transition"
        >
          Sign out
        </button>
        <p className="mt-3 text-[10px] uppercase tracking-widest text-zinc-700 text-center">
          AiSOC · MIT-licensed AI SOC ·{' '}
          <Link
            href="/responder/triage"
            className="hover:text-zinc-500 underline-offset-2 hover:underline"
          >
            Back to triage
          </Link>
        </p>
      </div>

      {toast ? (
        <div
          role="status"
          className="fixed left-1/2 -translate-x-1/2 bottom-[calc(5rem+env(safe-area-inset-bottom))] z-40 px-4 py-2 rounded-lg bg-zinc-100 text-zinc-900 text-sm shadow-lg"
        >
          {toast}
        </div>
      ) : null}
    </div>
  );
}

// ─── Local components ───────────────────────────────────────────────────────

interface SectionProps {
  title: string;
  description?: string;
  children?: React.ReactNode;
  collapsed?: boolean;
  expanded?: boolean;
  onToggle?: () => void;
}

function Section({
  title,
  description,
  children,
  collapsed,
  expanded,
  onToggle,
}: SectionProps) {
  return (
    <section className="mt-5">
      <div className="px-1 mb-2 flex items-baseline justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-xs uppercase tracking-wider text-zinc-500">
            {title}
          </h2>
          {description ? (
            <p className="text-[11px] text-zinc-500/80 mt-1 leading-snug">
              {description}
            </p>
          ) : null}
        </div>
        {collapsed ? (
          <button
            type="button"
            onClick={onToggle}
            className="text-[11px] uppercase tracking-wider text-zinc-500 hover:text-zinc-300"
          >
            {expanded ? 'Hide' : 'Show'}
          </button>
        ) : null}
      </div>
      {children}
    </section>
  );
}

function PushStatusPill({ state }: { state: PushState }) {
  switch (state) {
    case 'subscribed':
      return <Pill tone="emerald" label="Active on this device" />;
    case 'granted-unsubscribed':
      return <Pill tone="amber" label="Allowed, not subscribed" />;
    case 'denied':
      return <Pill tone="red" label="Blocked by browser" />;
    case 'unsupported':
      return <Pill tone="zinc" label="Not supported" />;
    case 'idle':
    default:
      return <Pill tone="zinc" label="Off" />;
  }
}

function Pill({
  tone,
  label,
}: {
  tone: 'emerald' | 'amber' | 'red' | 'zinc';
  label: string;
}) {
  const palette: Record<typeof tone, string> = {
    emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    amber: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    red: 'bg-red-500/15 text-red-300 border-red-500/30',
    zinc: 'bg-zinc-800 text-zinc-400 border-zinc-700',
  };
  return (
    <span
      className={clsx(
        'inline-block text-[10px] uppercase tracking-wider px-2 py-0.5 rounded border',
        palette[tone],
      )}
    >
      {label}
    </span>
  );
}

function DiagRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <div className="text-[11px] uppercase tracking-wider text-zinc-500 shrink-0">
        {label}
      </div>
      <div
        className={clsx(
          'text-[11px] text-zinc-300 text-right break-all',
          mono && 'font-mono',
        )}
      >
        {value}
      </div>
    </div>
  );
}

function SkeletonList() {
  return (
    <ul
      className="rounded-xl border border-zinc-800/60 bg-zinc-900/20 divide-y divide-zinc-800/60 overflow-hidden"
      aria-hidden
    >
      {Array.from({ length: 2 }).map((_, i) => (
        <li key={i} className="px-4 py-3 flex items-center gap-3">
          <div className="flex-1">
            <div className="h-3 w-1/2 bg-zinc-800/80 rounded animate-pulse" />
            <div className="h-2.5 w-1/3 bg-zinc-800/60 rounded mt-2 animate-pulse" />
          </div>
          <div className="h-7 w-16 bg-zinc-800/60 rounded animate-pulse" />
        </li>
      ))}
    </ul>
  );
}
