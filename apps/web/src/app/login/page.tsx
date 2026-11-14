'use client';

/**
 * Desktop console login.
 *
 * Email + password against ``POST /api/v1/auth/login`` for the open-source
 * console. The mobile responder PWA at ``/responder/login`` uses passkeys; this
 * page is the desktop counterpart and the link target from the responder login
 * footer ("Sign in on desktop").
 *
 * Demo credentials live in `services/api/app/api/v1/dev_auth.py`:
 *   demo@example.com / aisoc-demo
 */

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useState } from 'react';
import {
  API_BASE,
  authApi,
  isMfaChallenge,
  mfaApi,
  onboardingApi,
  type MfaChallenge,
  type MfaEnrollment,
} from '@/lib/api';
import { isDemoMode } from '@/lib/demoMode';

type Phase = 'idle' | 'pending' | 'success' | 'error';

export const dynamic = 'force-dynamic';

// Supplied by the build, never written here. Next inlines NEXT_PUBLIC_* into
// the client bundle wherever they are referenced, so a literal in this module
// would put a working login pair into every image the project ships —
// including one built with demo mode off for somebody's own deployment.
// Gating the *render* on isDemoMode() hides the panel; it does not remove the
// strings. Only the demo build passes these.
const DEMO_EMAIL = process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL?.trim() ?? '';
const DEMO_PASSWORD = process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD?.trim() ?? '';
const HAS_DEMO_CREDENTIALS = Boolean(DEMO_EMAIL && DEMO_PASSWORD);

/**
 * Sanitize the ``?next=`` redirect target so a crafted link can't be used to
 * bounce an authenticated user to an attacker-controlled host.
 *
 * Only same-origin relative paths are allowed. Anything that looks like an
 * absolute URL (``http://``, ``//evil.com``), a JS scheme, or a path that
 * doesn't start with a single ``/`` is replaced with the dashboard default.
 */
function sanitizeNext(raw: string | null | undefined): string {
  const fallback = '/dashboard';
  if (!raw) return fallback;
  // Reject protocol-relative URLs (//evil.com) and backslash variants
  // (some browsers normalize \\ to //).
  if (raw.startsWith('//') || raw.startsWith('\\\\')) return fallback;
  // Require a single leading slash. This rejects ``http://...``,
  // ``javascript:...``, ``data:...``, ``mailto:...``, and bare paths
  // like ``dashboard`` (which would resolve relative to the current URL).
  if (!raw.startsWith('/')) return fallback;
  // Reject ``/\evil.com`` style tricks.
  if (raw.startsWith('/\\')) return fallback;
  return raw;
}

function LoginInner() {
  const router = useRouter();
  const search = useSearchParams();
  const next = sanitizeNext(search?.get('next'));

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [sso, setSso] = useState<{ sso_enabled: boolean; provider: string; login_label: string; local_login_enabled: boolean } | null>(null);
  const [challenge, setChallenge] = useState<MfaChallenge | null>(null);
  const [code, setCode] = useState('');
  const [enrolment, setEnrolment] = useState<MfaEnrollment | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  // An SSO round-trip lands here with the session in the fragment; consume
  // it before the stored-token redirect below can read a still-empty store.
  const [handoffPending] = useState(() =>
    typeof window !== 'undefined' && window.location.hash.includes('access_token='),
  );
  useEffect(() => {
    if (!handoffPending) return;
    authApi.completeSsoHandoff().then((ok) => {
      if (ok) router.replace(next);
      else setError('The SSO sign-in could not be completed. Try again or sign in with your password.');
    });
  }, [handoffPending, next, router]);

  useEffect(() => {
    if (authApi.isAuthenticated()) {
      router.replace(next);
    }
  }, [next, router]);

  useEffect(() => {
    let alive = true;
    authApi.ssoStatus().then((s) => {
      if (alive) setSso(s);
    });
    return () => {
      alive = false;
    };
  }, []);

/**
 * Where to send someone after they sign in.
 *
 * A tenant with nothing connected and no alerts used to land on
 * `/dashboard`: every tile zero and nothing saying what to do next. They
 * go to the setup wizard instead.
 *
 * Only when the caller did not ask for somewhere specific. An expired
 * session that bounced someone off `/alerts` should return them to
 * `/alerts`, not to a wizard they have seen before.
 *
 * Never throws. Failing to work out where to land is not a reason to
 * fail a sign-in that already succeeded.
 */
async function landingRoute(requested: string): Promise<string> {
  if (requested && requested !== '/dashboard') return requested;
  try {
    const status = await onboardingApi.status();
    return status.first_run ? '/onboarding' : requested || '/dashboard';
  } catch {
    return requested || '/dashboard';
  }
}

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (phase === 'pending') return;
    setPhase('pending');
    setError(null);

    try {
      const result = await authApi.login(email.trim(), password);
      // The password was right and no session was issued: this account, or
      // this tenant, requires a second factor.
      if (isMfaChallenge(result)) {
        setChallenge(result);
        setPhase('idle');
        return;
      }
      setPhase('success');
      router.replace(await landingRoute(next));
    } catch (err) {
      console.error('[login] failed', err);
      setPhase('error');
      const message = err instanceof Error ? err.message : 'Login failed.';
      // Map the common 401 to something a human understands.
      if (/401|incorrect/i.test(message)) {
        setError('Email or password incorrect.');
      } else {
        setError(message);
      }
    }
  };

  const beginEnrolment = async () => {
    if (!challenge || phase === 'pending') return;
    setPhase('pending');
    setError(null);
    try {
      setEnrolment(await mfaApi.enrollBegin(challenge.mfa_token));
      setPhase('idle');
    } catch (err) {
      setPhase('error');
      setError(err instanceof Error ? err.message : 'Could not start enrolment.');
    }
  };

  const submitCode = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!challenge || phase === 'pending') return;
    setPhase('pending');
    setError(null);
    try {
      // Enrolling and verifying are different endpoints. The first
      // confirms a secret the user has just scanned and signs them in; the
      // second completes a sign-in against a factor they already hold.
      if (enrolment) {
        const confirmed = await mfaApi.enrollConfirm(code.trim(), challenge.mfa_token);
        setRecoveryCodes(confirmed.recovery_codes);
        if (confirmed.access_token) {
          await authApi.adoptSession(confirmed.access_token, confirmed.refresh_token ?? '');
        }
        setPhase('success');
        return;
      }
      await authApi.completeMfa(challenge.mfa_token, code.trim());
      setPhase('success');
      router.replace(await landingRoute(next));
    } catch (err) {
      setPhase('error');
      const message = err instanceof Error ? err.message : 'Verification failed.';
      // A challenge is short-lived, and "that code is not valid" is the
      // wrong thing to tell someone whose five minutes ran out.
      setError(
        /expired/i.test(message)
          ? 'That sign-in attempt expired. Enter your password again.'
          : 'That code is not valid. Check your authenticator, or use a recovery code.',
      );
    }
  };

  const useDemo = () => {
    setEmail(DEMO_EMAIL);
    setPassword(DEMO_PASSWORD);
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 antialiased flex flex-col">
      <div className="flex-1 flex items-center justify-center px-6 py-16">
        <div className="w-full max-w-md">
          {/* Brand */}
          <div className="flex flex-col items-center text-center mb-10">
            <Link
              href="/"
              className="w-14 h-14 rounded-2xl bg-indigo-600 flex items-center justify-center mb-5 hover:bg-indigo-500 transition"
              aria-label="Back to AiSOC home"
            >
              <svg
                className="w-8 h-8 text-white"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.75}
                  d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                />
              </svg>
            </Link>
            <h1 className="text-2xl font-semibold tracking-tight">
              Sign in to AiSOC
            </h1>
            <p className="text-sm text-zinc-400 mt-2 leading-relaxed">
              Open-source AI SOC console. Sign in with your tenant&rsquo;s
              account.
            </p>
          </div>

          {/* Demo banner — demo mode only, and only when the build supplied
              credentials. These are seeded by a public demo and exist nowhere
              else, so on a self-hosted deployment this rendered a "Use demo"
              button that fails and told the operator's own users to sign in
              with an account on somebody else's instance. */}
          {isDemoMode() && HAS_DEMO_CREDENTIALS && (
          <div className="mb-6 rounded-xl border border-indigo-500/30 bg-indigo-500/5 px-4 py-3 text-sm">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-medium text-indigo-300">Public demo</p>
                <p className="text-xs text-zinc-400 mt-0.5">
                  <code className="text-zinc-300">{DEMO_EMAIL}</code> /{' '}
                  <code className="text-zinc-300">{DEMO_PASSWORD}</code>
                </p>
              </div>
              <button
                type="button"
                onClick={useDemo}
                className="shrink-0 rounded-lg border border-indigo-500/40 bg-indigo-500/10 px-3 py-1.5 text-xs font-medium text-indigo-200 hover:bg-indigo-500/20 transition"
              >
                Use demo
              </button>
            </div>
          </div>
          )}

          {/* Second factor. Replaces the password form rather than sitting
              beside it: the password has already been accepted, and leaving
              it on screen invites someone to retype it instead of reading
              their authenticator. */}
          {challenge ? (
            <form onSubmit={submitCode} className="space-y-4" noValidate data-testid="mfa-challenge">
              <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-3 text-sm text-zinc-300">
                {challenge.mfa_enrollment_required
                  ? 'Your organisation requires a second factor and this account has not set one up yet. Finish setting it up to sign in.'
                  : 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.'}
              </div>

              {/* Enrolment happens here rather than behind a link to
                  /settings/mfa: this user has a correct password and no
                  session, so every authenticated route would bounce them
                  straight back to this page. */}
              {challenge.mfa_enrollment_required && !enrolment ? (
                <button
                  type="button"
                  onClick={beginEnrolment}
                  disabled={phase === 'pending'}
                  className="w-full inline-flex items-center justify-center rounded-xl bg-indigo-500 hover:bg-indigo-400 text-white font-medium py-3 px-4 transition disabled:bg-zinc-800 disabled:text-zinc-500"
                >
                  {phase === 'pending' ? 'Preparing…' : 'Set up two-factor authentication'}
                </button>
              ) : (
                <>
                  {enrolment ? (
                    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 px-4 py-3 space-y-2">
                      <p className="text-xs text-zinc-400">
                        Add this key to your authenticator app, then enter the code it shows.
                      </p>
                      <code className="block break-all rounded-lg bg-zinc-950 px-3 py-2 text-xs tracking-wider text-indigo-300">
                        {enrolment.secret}
                      </code>
                      <a
                        href={enrolment.otpauth_uri}
                        className="inline-block text-xs text-indigo-400 hover:text-indigo-300 underline-offset-2 hover:underline"
                      >
                        Open in your authenticator app
                      </a>
                    </div>
                  ) : null}

                  {recoveryCodes ? (
                    <div className="rounded-xl border border-amber-500/40 bg-amber-500/5 px-4 py-3 space-y-2">
                      <p className="text-xs font-medium text-amber-300">
                        Save these recovery codes. They are shown once.
                      </p>
                      <ul className="grid grid-cols-2 gap-1 font-mono text-[11px] text-zinc-300">
                        {recoveryCodes.map((rc) => (
                          <li key={rc}>{rc}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}

                  <label className="block">
                    <span className="block text-xs uppercase tracking-wider text-zinc-500 mb-2">
                      Verification code
                    </span>
                    <input
                      type="text"
                      // `one-time-code` is what lets a phone offer the code
                      // from the notification shade; without it the user
                      // switches apps and loses the page on iOS.
                      autoComplete="one-time-code"
                      inputMode="text"
                      autoCapitalize="characters"
                      spellCheck={false}
                      autoFocus
                      placeholder="123456"
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      disabled={phase === 'pending'}
                      required
                      className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-3 text-sm tracking-[0.3em] text-zinc-100 placeholder:tracking-normal placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 disabled:opacity-60"
                    />
                  </label>
                  {/* Navigating automatically would take the recovery
                      codes off the screen the moment they appeared, and
                      they are shown exactly once. */}
                  {recoveryCodes ? (
                    <button
                      type="button"
                      onClick={async () => router.replace(await landingRoute(next))}
                      className="w-full bg-indigo-500 hover:bg-indigo-400 text-white font-medium rounded-xl py-3 px-4 transition"
                    >
                      I have saved my recovery codes — continue
                    </button>
                  ) : (
                    <button
                      type="submit"
                      disabled={phase === 'pending' || !code}
                      className="w-full bg-indigo-500 hover:bg-indigo-400 active:bg-indigo-600 text-white font-medium rounded-xl py-3 px-4 transition disabled:bg-zinc-800 disabled:text-zinc-500"
                    >
                      {phase === 'pending' ? 'Verifying…' : enrolment ? 'Confirm' : 'Verify'}
                    </button>
                  )}
                </>
              )}

              {error ? (
                <div
                  role="alert"
                  className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2.5 text-xs text-red-300"
                >
                  {error}
                </div>
              ) : null}

              <button
                type="button"
                onClick={() => {
                  setChallenge(null);
                  setCode('');
                  setError(null);
                  setPassword('');
                  setEnrolment(null);
                  setRecoveryCodes(null);
                }}
                className="w-full text-xs text-zinc-500 hover:text-zinc-300 underline-offset-2 hover:underline"
              >
                Start over
              </button>
            </form>
          ) : (
          <>
          {/* Form */}
          {sso?.sso_enabled && (
            <div className="mb-4">
              <a
                href={`${API_BASE}/auth/${sso.provider === 'saml' ? 'saml/login' : 'oidc/login'}?redirect=${encodeURIComponent(next)}`}
                className="w-full inline-flex items-center justify-center gap-2 rounded-xl border border-indigo-500/40 bg-indigo-500/10 px-4 py-2.5 text-sm font-semibold text-indigo-200 hover:bg-indigo-500/20 transition"
                data-testid="sso-login-button"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75A2.25 2.25 0 004.5 12.75v6.75a2.25 2.25 0 002.25 2.25z" />
                </svg>
                {sso.login_label || 'Continue with SSO'}
              </a>
              {sso.local_login_enabled ? (
                <div className="my-4 flex items-center gap-3 text-[11px] uppercase tracking-widest text-zinc-600">
                  <span className="h-px flex-1 bg-zinc-800" />
                  or
                  <span className="h-px flex-1 bg-zinc-800" />
                </div>
              ) : null}
            </div>
          )}

          <form onSubmit={submit} className="space-y-4" noValidate>
            <label className="block">
              <span className="block text-xs uppercase tracking-wider text-zinc-500 mb-2">
                Email
              </span>
              <input
                type="email"
                autoComplete="username"
                inputMode="email"
                autoCapitalize="off"
                spellCheck={false}
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={phase === 'pending'}
                required
                className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 disabled:opacity-60"
              />
            </label>

            <label className="block">
              <span className="block text-xs uppercase tracking-wider text-zinc-500 mb-2">
                Password
              </span>
              <input
                type="password"
                autoComplete="current-password"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={phase === 'pending'}
                required
                className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 disabled:opacity-60"
              />
            </label>

            <button
              type="submit"
              disabled={phase === 'pending' || !email || !password}
              className="w-full bg-indigo-500 hover:bg-indigo-400 active:bg-indigo-600 text-white font-medium rounded-xl py-3 px-4 transition flex items-center justify-center gap-2 disabled:bg-zinc-800 disabled:text-zinc-500"
            >
              {phase === 'pending' ? (
                <>
                  <svg
                    className="w-4 h-4 animate-spin"
                    fill="none"
                    viewBox="0 0 24 24"
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
                  <span>Signing in…</span>
                </>
              ) : (
                <span>Sign in</span>
              )}
            </button>

            {error ? (
              <div
                role="alert"
                className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2.5 text-xs text-red-300"
              >
                {error}
              </div>
            ) : null}
          </form>
          </>
          )}

          {/* Footer hints */}
          <div className="mt-8 space-y-3 text-center">
            <p className="text-xs text-zinc-500">
              On a phone?{' '}
              <Link
                href="/responder/login"
                className="text-indigo-400 hover:text-indigo-300 underline-offset-2 hover:underline"
              >
                Use the responder PWA
              </Link>{' '}
              with passkeys.
            </p>
            <p className="text-[11px] text-zinc-600">
              <Link
                href="/"
                className="hover:text-zinc-400 underline-offset-2 hover:underline"
              >
                ← Back to home
              </Link>
            </p>
          </div>
        </div>
      </div>

      <div className="px-6 pb-[max(1rem,env(safe-area-inset-bottom))] pt-4 text-center">
        <p className="text-[10px] text-zinc-700 uppercase tracking-widest">
          AiSOC · MIT-licensed · Open-source AI SOC
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginInner />
    </Suspense>
  );
}
