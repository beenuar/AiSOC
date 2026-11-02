'use client';

/**
 * White-label branding, administered from the console.
 *
 * Wave 2, Phase 9.5.
 *
 * `GET`, `PUT`, asset upload and asset delete have all shipped at
 * `/api/v1/branding` since the white-label work landed. The console bound
 * only the read half — `brandingApi.get` and `brandingApi.logo`, both called
 * to paint the sidebar — so the product rendered a tenant's branding and
 * offered no way to set it. That is the "exists but nothing calls it" family
 * on the write side: the capability is complete, and the only route to it was
 * a curl command.
 *
 * Three things this panel has to get right:
 *
 * - **A tenant in no operator organisation gets a 409, and that is an
 *   answer.** There is genuinely nothing to brand. Rendering it as a failure
 *   would send an administrator to debug a working deployment, so it has its
 *   own state saying what to do instead.
 * - **The upload reasons are worth surfacing verbatim.** The route refuses an
 *   SVG the sanitiser rejected, a file whose bytes disagree with its declared
 *   type, and an unsupported type — three different next actions. "Upload
 *   failed" collapses them into one.
 * - **A failed read never renders plausible branding.** The fields below are
 *   what a recipient of an approval email sees; a fabricated `support_url`
 *   invites an operator to believe a link they never set is live.
 */

import { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';

import { ApiError, brandingApi, type Branding, type BrandingUpdate } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';

function inputClass() {
  return 'w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:border-blue-500 focus:outline-none';
}

function describeError(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

/** The form's working copy. Separate from the server value so a failed save does not lose typing. */
interface Draft {
  product_name: string;
  primary_color: string;
  accent_color: string;
  support_email: string;
  support_url: string;
  sender_name: string;
  footer_text: string;
}

function draftFrom(branding: Branding): Draft {
  return {
    product_name: branding.product_name ?? '',
    primary_color: branding.primary_color ?? '',
    accent_color: branding.accent_color ?? '',
    support_email: branding.support_email ?? '',
    support_url: branding.support_url ?? '',
    sender_name: branding.sender_name ?? '',
    footer_text: branding.footer_text ?? '',
  };
}

/** Empty string means "unset" to this form and `null` to the route. */
function orNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

const HEX = /^#[0-9A-Fa-f]{6}$/;

export function BrandingPanel() {
  const [branding, setBranding] = useState<Branding | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [noOrg, setNoOrg] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const value = await brandingApi.get();
      setBranding(value);
      setDraft(draftFrom(value));
      setLoadError(null);
      setNoOrg(false);
    } catch (err) {
      setBranding(null);
      setDraft(null);
      setLoadError(describeError(err, 'Could not load branding.'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const set = (key: keyof Draft, value: string) =>
    setDraft((current) => (current === null ? current : { ...current, [key]: value }));

  const save = async () => {
    if (draft === null) return;
    for (const [label, value] of [
      ['Primary colour', draft.primary_color],
      ['Accent colour', draft.accent_color],
    ] as const) {
      if (value.trim() !== '' && !HEX.test(value.trim())) {
        toast.error(`${label} must be a six-digit hex value such as #1d4ed8`);
        return;
      }
    }
    // Checked here as well as at the route so the operator is told which
    // field is wrong before a round trip, not after a 422 naming the body.
    if (draft.support_url.trim() !== '' && !draft.support_url.trim().startsWith('https://')) {
      toast.error('Support URL must be an https:// address — it is rendered as a link in email and PDF reports');
      return;
    }

    const body: BrandingUpdate = {
      product_name: orNull(draft.product_name),
      primary_color: orNull(draft.primary_color),
      accent_color: orNull(draft.accent_color),
      support_email: orNull(draft.support_email),
      support_url: orNull(draft.support_url),
      sender_name: orNull(draft.sender_name),
      footer_text: orNull(draft.footer_text),
    };

    setBusy(true);
    try {
      const saved = await brandingApi.update(body);
      setBranding(saved);
      setDraft(draftFrom(saved));
      toast.success('Branding saved. New approval emails and reports use it.');
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setNoOrg(true);
        toast.error('This tenant belongs to no operator organisation, so there is nothing to brand.');
      } else {
        toast.error(describeError(err, 'Could not save branding'));
      }
    } finally {
      setBusy(false);
    }
  };

  const upload = async (kind: 'logo' | 'favicon', file: File | null) => {
    if (!file) return;
    setBusy(true);
    try {
      const asset = await brandingApi.uploadAsset(kind, file);
      await load();
      toast.success(
        asset.sanitized
          ? `${kind === 'logo' ? 'Logo' : 'Favicon'} uploaded. Scriptable content was removed from the SVG before storing it.`
          : `${kind === 'logo' ? 'Logo' : 'Favicon'} uploaded.`,
      );
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setNoOrg(true);
      }
      toast.error(describeError(err, 'Could not upload the asset'));
    } finally {
      setBusy(false);
    }
  };

  const removeAsset = async (kind: 'logo' | 'favicon') => {
    setBusy(true);
    try {
      await brandingApi.deleteAsset(kind);
      await load();
      toast.success(`${kind === 'logo' ? 'Logo' : 'Favicon'} removed. The default mark is used again.`);
    } catch (err) {
      toast.error(describeError(err, 'Could not remove the asset'));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid="branding-panel">
      <div className="border-b border-gray-800 px-6 py-4">
        <h2 className="text-base font-semibold text-gray-100">Branding</h2>
        <p className="mt-1 text-sm text-gray-500">
          The product name, colours and support details this organisation&apos;s
          tenants see — and that appear in approval emails and exported
          reports.
        </p>
      </div>

      <div className="space-y-5 px-6 py-5">
        {loadError ? (
          <EmptyState title="Could not load branding" description={loadError} />
        ) : loading ? (
          <EmptyState title="Loading branding…" description="" />
        ) : draft === null ? (
          <EmptyState title="Could not load branding" description="The server did not return a branding record." />
        ) : (
          <>
            {noOrg ? (
              <div
                data-testid="branding-no-org"
                className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-4 text-sm text-amber-200"
              >
                This tenant belongs to no operator organisation, so there is
                nothing to brand. Create an organisation and add this tenant to
                its portfolio first; the fields below will then save.
              </div>
            ) : null}

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="text-sm">
                <span className="mb-1 block text-gray-400">Product name</span>
                <input
                  className={inputClass()}
                  value={draft.product_name}
                  onChange={(e) => set('product_name', e.target.value)}
                  aria-label="Product name"
                  placeholder="AiSOC"
                />
              </label>
              <label className="text-sm">
                <span className="mb-1 block text-gray-400">Email sender name</span>
                <input
                  className={inputClass()}
                  value={draft.sender_name}
                  onChange={(e) => set('sender_name', e.target.value)}
                  aria-label="Email sender name"
                  placeholder="Security Operations"
                />
              </label>
              <label className="text-sm">
                <span className="mb-1 block text-gray-400">Primary colour</span>
                <input
                  className={inputClass()}
                  value={draft.primary_color}
                  onChange={(e) => set('primary_color', e.target.value)}
                  aria-label="Primary colour"
                  placeholder="#1d4ed8"
                />
              </label>
              <label className="text-sm">
                <span className="mb-1 block text-gray-400">Accent colour</span>
                <input
                  className={inputClass()}
                  value={draft.accent_color}
                  onChange={(e) => set('accent_color', e.target.value)}
                  aria-label="Accent colour"
                  placeholder="#0ea5e9"
                />
              </label>
              <label className="text-sm">
                <span className="mb-1 block text-gray-400">Support email</span>
                <input
                  className={inputClass()}
                  value={draft.support_email}
                  onChange={(e) => set('support_email', e.target.value)}
                  aria-label="Support email"
                  placeholder="soc@example.com"
                />
              </label>
              <label className="text-sm">
                <span className="mb-1 block text-gray-400">Support URL</span>
                <input
                  className={inputClass()}
                  value={draft.support_url}
                  onChange={(e) => set('support_url', e.target.value)}
                  aria-label="Support URL"
                  placeholder="https://support.example.com"
                />
              </label>
            </div>

            <label className="block text-sm">
              <span className="mb-1 block text-gray-400">Footer text</span>
              <textarea
                className={`${inputClass()} min-h-[72px]`}
                value={draft.footer_text}
                onChange={(e) => set('footer_text', e.target.value)}
                aria-label="Footer text"
                placeholder="Shown at the foot of emails and exported reports."
              />
            </label>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => void save()}
                disabled={busy}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
              >
                {busy ? 'Working…' : 'Save branding'}
              </button>
              {branding?.is_white_labelled ? (
                <span className="text-xs text-gray-500">
                  This organisation is white-labelled.
                </span>
              ) : null}
            </div>

            <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-950/40 p-4">
              <h3 className="text-sm font-medium text-gray-200">Logo and favicon</h3>
              <p className="text-xs text-gray-500">
                SVG, PNG, JPEG or WebP. An SVG is sanitised on upload and what is
                stored is the sanitised output — nothing re-sanitises when it is
                rendered.
              </p>
              {(['logo', 'favicon'] as const).map((kind) => (
                <div key={kind} className="flex flex-wrap items-center gap-3">
                  <span className="w-20 text-sm capitalize text-gray-300">{kind}</span>
                  <input
                    type="file"
                    accept="image/svg+xml,image/png,image/jpeg,image/webp"
                    aria-label={`Upload ${kind}`}
                    disabled={busy}
                    onChange={(e) => void upload(kind, e.target.files?.[0] ?? null)}
                    className="text-xs text-gray-400 file:mr-3 file:rounded file:border file:border-gray-700 file:bg-gray-900 file:px-3 file:py-1.5 file:text-xs file:text-gray-200"
                  />
                  <button
                    type="button"
                    onClick={() => void removeAsset(kind)}
                    disabled={busy}
                    className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-gray-200 hover:bg-gray-800 disabled:opacity-40"
                  >
                    Remove
                  </button>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
