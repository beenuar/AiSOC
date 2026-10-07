'use client';

/**
 * Two-factor authentication: your own factor, and the tenant policy.
 *
 * Fix pass 4.2. The console had no second factor at all — passkeys existed
 * on the mobile responder only, so the surface an analyst works from all
 * day was single-factor and no administrator could change that.
 *
 * Enrolling from a *sign-in challenge* is not done here. A user whose
 * tenant has just started requiring a factor holds a correct password and
 * no session, so every authenticated route bounces them to `/login` — and
 * that is where their enrolment lives.
 */

import { useCallback, useEffect, useState } from 'react';
import { mfaApi, type MfaEnrollment, type MfaStatus } from '@/lib/api';

type Phase = 'idle' | 'pending';

export function MfaView() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [enrolment, setEnrolment] = useState<MfaEnrollment | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState('');
  const [phase, setPhase] = useState<Phase>('idle');
  const [error, setError] = useState<string | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await mfaApi.status());
      setLoadError(null);
    } catch (err) {
      // An honest failure, not a zeroed card: "not enrolled" and "we could
      // not find out" are different answers and only one of them is safe
      // to act on.
      setStatus(null);
      setLoadError(err instanceof Error ? err.message : 'Could not read your MFA status.');
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const begin = async () => {
    setPhase('pending');
    setError(null);
    try {
      setEnrolment(await mfaApi.enrollBegin());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start enrolment.');
    } finally {
      setPhase('idle');
    }
  };

  const confirm = async (event: React.FormEvent) => {
    event.preventDefault();
    setPhase('pending');
    setError(null);
    try {
      const confirmed = await mfaApi.enrollConfirm(code.trim());
      setRecoveryCodes(confirmed.recovery_codes);
      setEnrolment(null);
      setCode('');
      await refresh();
    } catch {
      setError('That code is not valid. Check that your phone’s clock is correct.');
    } finally {
      setPhase('idle');
    }
  };

  const disable = async (event: React.FormEvent) => {
    event.preventDefault();
    setPhase('pending');
    setError(null);
    try {
      await mfaApi.disable(code.trim());
      setCode('');
      setRecoveryCodes(null);
      await refresh();
    } catch {
      setError('That code is not valid, so the factor was not removed.');
    } finally {
      setPhase('idle');
    }
  };

  const setPolicy = async (requireTotp: boolean) => {
    setPolicyError(null);
    try {
      await mfaApi.setPolicy(requireTotp);
      await refresh();
    } catch (err) {
      const message = err instanceof Error ? err.message : '';
      setPolicyError(
        /403/.test(message)
          ? 'Changing the tenant policy needs the settings:write permission.'
          : 'Could not change the tenant policy.',
      );
    }
  };

  return (
    <div className="space-y-6 max-w-2xl">
      <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
        <header>
          <h2 className="text-base font-semibold text-zinc-100">Two-factor authentication</h2>
          <p className="text-sm text-zinc-400 mt-1">
            A time-based code from an authenticator app, in addition to your password.
          </p>
        </header>

        {loadError ? (
          <p role="alert" className="text-sm text-red-300">
            {loadError}
          </p>
        ) : status === null ? (
          <p className="text-sm text-zinc-500">Checking…</p>
        ) : (
          <>
            <p className="text-sm text-zinc-300">
              {status.enrolled
                ? `Enrolled. ${status.recovery_codes_remaining} recovery code${status.recovery_codes_remaining === 1 ? '' : 's'} left.`
                : 'Not enrolled.'}
              {status.tenant_requires_totp ? ' Your organisation requires it.' : ''}
            </p>

            {!status.enrolled && !enrolment ? (
              <button
                type="button"
                onClick={begin}
                disabled={phase === 'pending'}
                className="rounded-lg bg-indigo-500 hover:bg-indigo-400 px-4 py-2 text-sm font-medium text-white transition disabled:bg-zinc-800 disabled:text-zinc-500"
              >
                Set up
              </button>
            ) : null}

            {enrolment ? (
              <form onSubmit={confirm} className="space-y-3">
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
                <input
                  type="text"
                  autoComplete="one-time-code"
                  placeholder="123456"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-100"
                />
                <button
                  type="submit"
                  disabled={phase === 'pending' || !code}
                  className="rounded-lg bg-indigo-500 hover:bg-indigo-400 px-4 py-2 text-sm font-medium text-white transition disabled:bg-zinc-800 disabled:text-zinc-500"
                >
                  Confirm
                </button>
              </form>
            ) : null}

            {recoveryCodes ? (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 px-4 py-3 space-y-2">
                <p className="text-xs font-medium text-amber-300">
                  Save these recovery codes. They are shown once and each works once.
                </p>
                <ul className="grid grid-cols-2 gap-1 font-mono text-[11px] text-zinc-300">
                  {recoveryCodes.map((rc) => (
                    <li key={rc}>{rc}</li>
                  ))}
                </ul>
              </div>
            ) : null}

            {status.enrolled && !enrolment ? (
              <form onSubmit={disable} className="space-y-2 border-t border-zinc-800 pt-4">
                <p className="text-xs text-zinc-500">
                  Removing your factor needs a current code, so a stolen session cannot strip the
                  thing protecting it.
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    autoComplete="one-time-code"
                    placeholder="Code or recovery code"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-100"
                  />
                  <button
                    type="submit"
                    disabled={phase === 'pending' || !code}
                    className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm font-medium text-red-300 transition hover:bg-red-500/20 disabled:opacity-50"
                  >
                    Remove
                  </button>
                </div>
              </form>
            ) : null}

            {error ? (
              <p role="alert" className="text-sm text-red-300">
                {error}
              </p>
            ) : null}
          </>
        )}
      </section>

      <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-3">
        <header>
          <h2 className="text-base font-semibold text-zinc-100">Require it across this tenant</h2>
          <p className="text-sm text-zinc-400 mt-1">
            Everyone signs in with a second factor. Members who have not enrolled are asked to set
            one up at their next sign-in rather than being locked out.
          </p>
        </header>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setPolicy(!(status?.tenant_requires_totp ?? false))}
            disabled={status === null}
            className="rounded-lg border border-zinc-700 bg-zinc-800/60 px-4 py-2 text-sm font-medium text-zinc-200 transition hover:bg-zinc-800 disabled:opacity-50"
          >
            {status?.tenant_requires_totp ? 'Stop requiring' : 'Require for everyone'}
          </button>
          <span className="text-xs text-zinc-500">
            {status?.tenant_requires_totp ? 'Currently required' : 'Currently optional'}
          </span>
        </div>
        {policyError ? (
          <p role="alert" className="text-sm text-red-300">
            {policyError}
          </p>
        ) : null}
      </section>
    </div>
  );
}
