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
 *   demo@aisoc.dev / aisoc-demo
 */

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useState } from 'react';
import { authApi } from '@/lib/api';

type Phase = 'idle' | 'pending' | 'success' | 'error';

export const dynamic = 'force-dynamic';

const DEMO_EMAIL = 'demo@aisoc.dev';
const DEMO_PASSWORD = 'aisoc-demo';

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

  useEffect(() => {
    if (authApi.isAuthenticated()) {
      router.replace(next);
    }
  }, [next, router]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (phase === 'pending') return;
    setPhase('pending');
    setError(null);

    try {
      await authApi.login(email.trim(), password);
      setPhase('success');
      router.replace(next);
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
              Open-source AI SOC console. Use the demo credentials below or
              your own tenant&rsquo;s account.
            </p>
          </div>

          {/* Demo banner */}
          <div className="mb-6 rounded-xl border border-indigo-500/30 bg-indigo-500/5 px-4 py-3 text-sm">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-medium text-indigo-300">Public demo</p>
                <p className="text-xs text-zinc-400 mt-0.5">
                  <code className="text-zinc-300">demo@aisoc.dev</code> /{' '}
                  <code className="text-zinc-300">aisoc-demo</code>
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

          {/* Form */}
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
                ← Back to tryaisoc.com
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
