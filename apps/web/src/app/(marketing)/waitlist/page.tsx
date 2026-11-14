'use client';

/**
 * `/waitlist` — managed-instance signup landing page (T6.1).
 *
 * This is the public marketing surface for `tryaisoc.com`. The page
 * collects email + company + role + current SOC stack + motivation,
 * POSTs to `/v1/waitlist/signup` (rate-limited per-IP on the API side),
 * and then flips into a success state.
 *
 * The form is intentionally *minimal* — every field we ask for has to
 * justify itself in terms of how it changes the conversation the sales
 * team has when they reach out. Today that's:
 *
 *   • email     — how we reach them.
 *   • company   — sizing / prioritisation.
 *   • role      — "are we talking to a champion or a buyer?".
 *   • soc_stack — surface which connectors they care about so the demo
 *                 lands on real plumbing instead of synthetic data.
 *   • motivation— the "why now?" we'd otherwise have to mine off the
 *                 first sales call.
 *
 * Anything else is friction we can collect later inside the product
 * once they're logged in. Keeping the form tight is one of the few
 * conversion levers we have on a B2B-SOC waitlist.
 *
 * The visual chrome (sticky nav, dark surface, brand colour, footer)
 * is rendered by `(marketing)/layout.tsx` so this page is content-only
 * (ISSUE-006 shell unification, 2026-06-29). The Tailwind classes are
 * deliberately the same ones the rest of the marketing site uses so we
 * don't grow the design surface for a single page.
 */

import { useMemo, useState } from 'react';


// ---------------------------------------------------------------------------
// Form schema constants
// ---------------------------------------------------------------------------

const SOC_STACK_OPTIONS: readonly string[] = [
  'Splunk',
  'Microsoft Sentinel',
  'Elastic Security',
  'Chronicle / SecOps',
  'CrowdStrike',
  'SentinelOne',
  'Microsoft Defender',
  'Carbon Black',
  'Okta',
  'AWS GuardDuty',
  'GCP SCC',
  'Cloudflare',
  'Snowflake',
  'Datadog',
  'In-house scripts',
  'Other',
];

const SUBMIT_ENDPOINT = '/api/v1/waitlist/signup';

type FormState = {
  email: string;
  company: string;
  role: string;
  socStack: Set<string>;
  motivation: string;
};

const INITIAL_FORM_STATE: FormState = {
  email: '',
  company: '',
  role: '',
  socStack: new Set(),
  motivation: '',
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function WaitlistPage() {
  const [form, setForm] = useState<FormState>(() => ({
    ...INITIAL_FORM_STATE,
    socStack: new Set(),
  }));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const canSubmit = useMemo(() => {
    return (
      !!form.email.trim() &&
      !!form.company.trim() &&
      !!form.role.trim() &&
      !!form.motivation.trim()
    );
  }, [form]);

  const toggleStack = (option: string) => {
    setForm((prev) => {
      const next = new Set(prev.socStack);
      if (next.has(option)) {
        next.delete(option);
      } else {
        next.add(option);
      }
      return { ...prev, socStack: next };
    });
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit || submitting) return;

    setSubmitting(true);
    setError(null);

    try {
      const response = await fetch(SUBMIT_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: form.email.trim(),
          company: form.company.trim(),
          role: form.role.trim(),
          soc_stack: Array.from(form.socStack),
          motivation: form.motivation.trim(),
        }),
      });

      if (response.status === 429) {
        setError(
          'Too many signups from your network. Please try again in a few minutes.',
        );
        return;
      }

      if (!response.ok) {
        const detail = await response.text().catch(() => '');
        setError(
          `Could not submit (HTTP ${response.status}). ${
            detail ? detail.slice(0, 240) : 'Please try again or email hello@tryaisoc.com.'
          }`,
        );
        return;
      }

      setSuccess(true);
    } catch (err) {
      setError(
        `Network error: ${(err as Error).message}. Please try again or email hello@tryaisoc.com.`,
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      {/* Hero */}
      <section className="px-6 pt-32 pb-12">
        <div className="mx-auto max-w-3xl">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-brand-500/20 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
              Invite-only beta · tryaisoc.com
            </span>
            <span className="text-xs text-gray-500">
              We typically respond within 5 business days.
            </span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight text-white md:text-5xl">
            Run AiSOC as a managed service —
            <br />
            <span className="text-brand-300">invite-only beta.</span>
          </h1>
          <p className="mt-5 max-w-2xl text-lg leading-relaxed text-gray-400">
            Skip the Kubernetes cluster. We host the same MIT-licensed
            agent loop on <code className="rounded bg-white/[0.05] px-1 py-0.5 text-sm">tryaisoc.com</code>,
            ship it on a dedicated tenant with your own connectors and
            credential vault, and put your team in front of real
            investigations on day one. Self-hosting stays a first-class
            option — this page exists for the teams that would rather
            we ran the substrate for them.
          </p>
        </div>
      </section>

      {/* Form OR success card */}
      <section className="px-6 pb-24">
        <div className="mx-auto max-w-3xl">
          {success ? (
            <SuccessCard />
          ) : (
            <form
              onSubmit={handleSubmit}
              className="space-y-6 rounded-2xl border border-white/10 bg-white/[0.02] p-8"
              aria-label="Managed instance waitlist signup"
            >
              <div className="grid gap-5 md:grid-cols-2">
                <Field
                  id="waitlist-email"
                  label="Work email"
                  required
                  hint="We won't share this — used to invite you."
                >
                  <input
                    id="waitlist-email"
                    type="email"
                    autoComplete="email"
                    required
                    value={form.email}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, email: e.target.value }))
                    }
                    className={inputClass}
                    placeholder="you@company.com"
                    maxLength={320}
                  />
                </Field>

                <Field
                  id="waitlist-company"
                  label="Company"
                  required
                  hint="Whoever cuts the security budget."
                >
                  <input
                    id="waitlist-company"
                    type="text"
                    autoComplete="organization"
                    required
                    value={form.company}
                    onChange={(e) =>
                      setForm((prev) => ({ ...prev, company: e.target.value }))
                    }
                    className={inputClass}
                    placeholder="Acme Inc"
                    maxLength={200}
                  />
                </Field>
              </div>

              <Field
                id="waitlist-role"
                label="Your role"
                required
                hint='e.g. "SOC Manager", "Director of Security", "Detection Engineer".'
              >
                <input
                  id="waitlist-role"
                  type="text"
                  autoComplete="organization-title"
                  required
                  value={form.role}
                  onChange={(e) =>
                    setForm((prev) => ({ ...prev, role: e.target.value }))
                  }
                  className={inputClass}
                  placeholder="SOC Manager"
                  maxLength={100}
                />
              </Field>

              <Field
                id="waitlist-soc-stack"
                label="Current SOC stack"
                hint="Pick everything in your detection / response stack today — drives which connectors we demo first."
              >
                <div
                  id="waitlist-soc-stack"
                  className="flex flex-wrap gap-2"
                  role="group"
                  aria-label="Current SOC stack"
                >
                  {SOC_STACK_OPTIONS.map((option) => {
                    const active = form.socStack.has(option);
                    return (
                      <button
                        type="button"
                        key={option}
                        onClick={() => toggleStack(option)}
                        aria-pressed={active}
                        className={
                          'rounded-full border px-3 py-1.5 text-xs font-medium transition ' +
                          (active
                            ? 'border-brand-500/40 bg-brand-500/10 text-brand-200'
                            : 'border-white/10 bg-white/[0.03] text-gray-300 hover:border-white/20 hover:bg-white/[0.06] hover:text-white')
                        }
                      >
                        {option}
                      </button>
                    );
                  })}
                </div>
              </Field>

              <Field
                id="waitlist-motivation"
                label="What are you trying to fix?"
                required
                hint="A sentence or two on the alert volume / staffing / time-to-investigate problem we should help with."
              >
                <textarea
                  id="waitlist-motivation"
                  required
                  rows={5}
                  value={form.motivation}
                  onChange={(e) =>
                    setForm((prev) => ({
                      ...prev,
                      motivation: e.target.value,
                    }))
                  }
                  className={textareaClass}
                  placeholder="We're drowning in low-fidelity EDR alerts. We need an agent that can investigate the first 80% so my two analysts can spend their time on the 20% that matters."
                  maxLength={4000}
                />
              </Field>

              {error && (
                <div
                  role="alert"
                  className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200"
                >
                  {error}
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <p className="text-xs text-gray-500">
                  We store this in our own database, not a marketing
                  SaaS. The team that reads it is the same team that
                  builds AiSOC.
                </p>
                <button
                  type="submit"
                  disabled={!canSubmit || submitting}
                  className={
                    'inline-flex items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition ' +
                    (canSubmit && !submitting
                      ? 'bg-brand-500 text-white hover:bg-brand-400'
                      : 'cursor-not-allowed bg-brand-500/40 text-white/70')
                  }
                  aria-disabled={!canSubmit || submitting}
                >
                  {submitting ? 'Sending…' : 'Request access'}
                  {!submitting && (
                    <svg
                      viewBox="0 0 20 20"
                      className="h-3.5 w-3.5"
                      fill="currentColor"
                      aria-hidden="true"
                    >
                      <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
                    </svg>
                  )}
                </button>
              </div>
            </form>
          )}
        </div>
      </section>

    </main>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

const inputClass =
  'w-full rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-sm text-white placeholder:text-gray-500 transition focus:border-brand-500/50 focus:outline-none focus:ring-2 focus:ring-brand-500/20';

const textareaClass = inputClass + ' min-h-[120px] resize-y leading-relaxed';

type FieldProps = {
  id: string;
  label: string;
  required?: boolean;
  hint?: string;
  children: React.ReactNode;
};

function Field({ id, label, required, hint, children }: FieldProps) {
  return (
    <div>
      <label
        htmlFor={id}
        className="flex items-baseline justify-between text-sm font-medium text-gray-200"
      >
        <span>
          {label}
          {required && (
            <span className="ml-1 text-brand-300" aria-hidden="true">
              *
            </span>
          )}
        </span>
      </label>
      {hint && (
        <p className="mt-1 text-xs text-gray-500" id={`${id}-hint`}>
          {hint}
        </p>
      )}
      <div className="mt-2">{children}</div>
    </div>
  );
}

function SuccessCard() {
  return (
    <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/[0.04] p-8 text-center">
      <div className="mx-auto mb-4 inline-flex h-12 w-12 items-center justify-center rounded-full border border-emerald-500/30 bg-emerald-500/10">
        <svg
          viewBox="0 0 20 20"
          className="h-6 w-6 text-emerald-300"
          fill="currentColor"
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M16.7 5.3a1 1 0 010 1.4l-7.5 7.5a1 1 0 01-1.4 0L3.3 9.7a1 1 0 011.4-1.4L8.5 12 15.3 5.3a1 1 0 011.4 0z"
            clipRule="evenodd"
          />
        </svg>
      </div>
      <h2 className="text-2xl font-semibold tracking-tight text-white">
        You&apos;re on the list.
      </h2>
      <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-gray-300">
        We&apos;ll be in touch within 5 business days. In the meantime,
        the entire substrate is open-source —{' '}
        <a
          href="https://github.com/beenuar/AiSOC"
          target="_blank"
          rel="noreferrer"
          className="text-brand-300 underline-offset-2 hover:underline"
        >
          clone it from GitHub
        </a>{' '}
        and run it locally with{' '}
        <code className="rounded bg-white/[0.05] px-1 py-0.5 text-xs">
          pnpm aisoc:demo
        </code>{' '}
        while you wait.
      </p>
    </div>
  );
}

