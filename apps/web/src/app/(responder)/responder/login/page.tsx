'use client';

/**
 * Mobile responder PWA login.
 *
 * Passkey-first by design: the on-call responder sets up a passkey on
 * their phone once and then never types a password again at 3am. We do
 * still expose an "email hint" field for FIDO authenticators that don't
 * support resident keys (rare, but happens with some hardware tokens).
 */

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import { passkeyApi } from '@/lib/api';
import {
  saveSession,
  profileFromAccessToken,
  isAuthenticated,
} from '@/lib/responder/auth';
import { getPasskey, isWebAuthnSupported } from '@/lib/responder/webauthn';

type Phase = 'idle' | 'pending' | 'success' | 'error';

export default function ResponderLoginPage() {
  const router = useRouter();
  const search = useSearchParams();
  const next = search?.get('next') || '/responder/triage';

  const [email, setEmail] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [supported, setSupported] = useState<boolean>(true);

  useEffect(() => {
    setSupported(isWebAuthnSupported());
    if (isAuthenticated()) {
      router.replace(next);
    }
  }, [next, router]);

  const handlePasskeyLogin = async (event: React.FormEvent) => {
    event.preventDefault();
    if (phase === 'pending') return;
    setPhase('pending');
    setError(null);

    try {
      const begin = await passkeyApi.authenticateBegin(email || undefined);
      const credential = await getPasskey(
        begin.publicKey as unknown as Parameters<typeof getPasskey>[0],
      );
      const tokens = await passkeyApi.authenticateFinish(
        begin.challenge,
        credential as unknown as Record<string, unknown>,
      );

      saveSession({
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        profile: profileFromAccessToken(tokens.access_token) ?? undefined,
      });
      setPhase('success');
      router.replace(next);
    } catch (err) {
      console.error('[responder] passkey login failed', err);
      setPhase('error');
      const message =
        err instanceof Error
          ? err.message
          : 'Passkey login failed. Please try again.';
      // The browser surfaces a generic NotAllowedError when the user cancels;
      // treat that as a soft state rather than a red error.
      if (
        err instanceof DOMException &&
        (err.name === 'NotAllowedError' || err.name === 'AbortError')
      ) {
        setError('Cancelled. Tap “Sign in with passkey” to try again.');
      } else {
        setError(message);
      }
    }
  };

  return (
    <div className="min-h-[100dvh] bg-zinc-950 text-zinc-100 antialiased flex flex-col">
      <div className="flex-1 flex flex-col justify-center px-6 max-w-md mx-auto w-full">
        {/* Brand mark */}
        <div className="flex flex-col items-center text-center mb-12">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center mb-5 shadow-lg shadow-indigo-500/20">
            <svg
              className="w-9 h-9 text-white"
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
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">
            AiSOC Responder
          </h1>
          <p className="text-sm text-zinc-400 mt-2 leading-relaxed">
            Tap to sign in with your phone&rsquo;s passkey. No passwords. No
            SMS. Just biometrics.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handlePasskeyLogin} className="space-y-4">
          <label className="block">
            <span className="block text-xs uppercase tracking-wider text-zinc-500 mb-2">
              Email <span className="normal-case text-zinc-600">(optional)</span>
            </span>
            <input
              type="email"
              autoComplete="username webauthn"
              inputMode="email"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="responder@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={phase === 'pending'}
              className="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-4 py-3.5 text-base text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 disabled:opacity-60"
            />
            <span className="block text-[11px] text-zinc-600 mt-1.5 leading-snug">
              Most phones use platform passkeys and don&rsquo;t need this.
            </span>
          </label>

          <button
            type="submit"
            disabled={!supported || phase === 'pending'}
            className="w-full bg-indigo-500 hover:bg-indigo-400 active:bg-indigo-600 text-white font-medium rounded-xl py-3.5 px-4 transition flex items-center justify-center gap-2 disabled:bg-zinc-800 disabled:text-zinc-500"
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
                <span>Waiting for passkey…</span>
              </>
            ) : (
              <>
                <svg
                  className="w-5 h-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={1.75}
                    d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"
                  />
                </svg>
                <span>Sign in with passkey</span>
              </>
            )}
          </button>

          {!supported ? (
            <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-300">
              This browser doesn&rsquo;t support passkeys. Use Safari on iOS,
              Chrome on Android, or open the desktop console.
            </div>
          ) : null}

          {error ? (
            <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2.5 text-xs text-red-300">
              {error}
            </div>
          ) : null}
        </form>

        {/* Footer hint */}
        <div className="mt-10 text-center">
          <p className="text-xs text-zinc-500">
            New device?{' '}
            <Link
              href="/login"
              className="text-indigo-400 hover:text-indigo-300 underline-offset-2 hover:underline"
            >
              Sign in on desktop
            </Link>{' '}
            and enroll a passkey from Settings.
          </p>
        </div>
      </div>

      <div className="px-6 pb-[max(1rem,env(safe-area-inset-bottom))] pt-4 text-center">
        <p className="text-[10px] text-zinc-700 uppercase tracking-widest">
          AiSOC · MIT-licensed AI SOC
        </p>
      </div>
    </div>
  );
}
