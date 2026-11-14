'use client';

/**
 * Universal-capture (Workstream 6) — operator surface for inbox tokens.
 *
 * For closed-proprietary tools we can't read or OAuth into, AiSOC mints a
 * per-tenant rotatable inbox URL. The vendor's existing webhook config
 * gets pointed at that URL; ``services/ingest`` resolves the token to a
 * tenant + vendor template and reuses the existing OCSF + Kafka pipeline.
 *
 * This component is the *management* UI: list templates, mint tokens,
 * copy the resulting URL exactly once, rotate or revoke. The "create"
 * flow looks like a modal because:
 *
 *   1. The plaintext token + URL are shown exactly once. We need a
 *      dedicated dismissable surface so the operator can copy them
 *      before they're permanently gone.
 *   2. The "rotate" flow has the same one-shot disclosure shape, so
 *      reusing the modal halves the disclosure UI.
 *
 * No SSR — entirely client-side, pure react-hooks. Mounting state is
 * keyed on ``open`` so we never run requests for a closed panel.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';

import {
  inboxApi,
  ApiError,
  type InboxTemplate,
  type InboxTokenListItem,
  type InboxTokenSecret,
} from '@/lib/api';

// ─── helpers ──────────────────────────────────────────────────────────────

function categoryLabel(cat: string): string {
  switch (cat) {
    case 'alerting':
      return 'Alerting';
    case 'cloud':
      return 'Cloud';
    case 'email':
      return 'Email';
    case 'generic':
      return 'Generic';
    case 'network':
      return 'Network';
    case 'siem':
      return 'SIEM / Syslog';
    case 'vcs':
      return 'Source control';
    default:
      return cat;
  }
}

const CATEGORY_ORDER: string[] = [
  'generic',
  'alerting',
  'siem',
  'cloud',
  'email',
  'vcs',
  'network',
];

function formatRelative(iso: string | null): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return '—';
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 30) return `${day}d ago`;
  return new Date(iso).toLocaleDateString();
}

async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// ─── one-shot disclosure modal ────────────────────────────────────────────

/**
 * Shown after a successful mint or rotate. Plaintext token / URL appears
 * here exactly once — closing this modal makes them permanently
 * unrecoverable, hence the loud copy buttons + warning.
 */
function SecretDisclosureModal({
  secret,
  onClose,
}: {
  secret: InboxTokenSecret;
  onClose: () => void;
}) {
  const handleCopy = async (text: string, label: string) => {
    const ok = await copyToClipboard(text);
    if (ok) toast.success(`Copied ${label}`);
    else toast.error(`Couldn't copy ${label} — copy by hand`);
  };

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-[80] flex items-center justify-center bg-black/70 px-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <motion.div
          className="w-full max-w-xl rounded-xl border border-amber-500/30 bg-gray-900 p-5 shadow-2xl"
          initial={{ y: 20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: 20, opacity: 0 }}
        >
          <div className="flex items-start justify-between gap-3 mb-3">
            <div>
              <h3 className="text-base font-semibold text-amber-200">
                Copy this URL — it won&apos;t be shown again
              </h3>
              <p className="text-xs text-gray-400 mt-1">
                Paste the URL into your vendor&apos;s webhook configuration. AiSOC
                stores only a fingerprint after this dialog closes; if you
                lose it, rotate the token to mint a new one.
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="text-gray-500 hover:text-gray-300 text-lg leading-none"
              aria-label="Close"
            >
              ×
            </button>
          </div>

          <label className="block text-xs text-gray-400 mb-1">
            Inbox URL
          </label>
          <div className="flex gap-2 mb-3">
            <input
              readOnly
              value={secret.inbox_url}
              className="flex-1 bg-gray-950 border border-gray-700 rounded-md px-2 py-1.5 text-xs text-gray-100 font-mono"
              onFocus={(e) => e.currentTarget.select()}
            />
            <button
              type="button"
              onClick={() => handleCopy(secret.inbox_url, 'URL')}
              className="bg-blue-600 hover:bg-blue-500 text-white text-xs px-3 py-1.5 rounded-md"
            >
              Copy URL
            </button>
          </div>

          <label className="block text-xs text-gray-400 mb-1">
            Token (already embedded in URL — exposed for SDK / scripted setups)
          </label>
          <div className="flex gap-2 mb-3">
            <input
              readOnly
              value={secret.token}
              className="flex-1 bg-gray-950 border border-gray-700 rounded-md px-2 py-1.5 text-xs text-gray-100 font-mono"
              onFocus={(e) => e.currentTarget.select()}
            />
            <button
              type="button"
              onClick={() => handleCopy(secret.token, 'token')}
              className="bg-gray-700 hover:bg-gray-600 text-white text-xs px-3 py-1.5 rounded-md"
            >
              Copy token
            </button>
          </div>

          {secret.has_hmac_secret && (
            <p className="text-xs text-gray-400 mb-3">
              HMAC verification is enabled. Configure your vendor to sign
              requests with header <code className="text-amber-200">X-Signature</code>{' '}
              or <code className="text-amber-200">X-Hub-Signature-256</code>.
            </p>
          )}

          <div className="flex justify-end pt-2 border-t border-gray-800">
            <button
              type="button"
              onClick={onClose}
              className="bg-gray-700 hover:bg-gray-600 text-white text-sm px-4 py-1.5 rounded-md"
            >
              Done
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}

// ─── mint form ────────────────────────────────────────────────────────────

function MintForm({
  templates,
  onCreated,
}: {
  templates: InboxTemplate[];
  onCreated: (secret: InboxTokenSecret) => void;
}) {
  const [templateId, setTemplateId] = useState<string>('');
  const [label, setLabel] = useState<string>('');
  const [hmacEnabled, setHmacEnabled] = useState<boolean>(false);
  const [hmacSecret, setHmacSecret] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);

  // Default to the first template in the catalog so the form is usable
  // without having to scroll the picker first.
  useEffect(() => {
    if (!templateId && templates.length > 0) {
      setTemplateId(templates[0].template_id);
    }
  }, [templates, templateId]);

  const grouped = useMemo(() => {
    const groups: Record<string, InboxTemplate[]> = {};
    for (const t of templates) {
      if (!groups[t.category]) groups[t.category] = [];
      groups[t.category].push(t);
    }
    return groups;
  }, [templates]);

  const orderedCategories = useMemo(() => {
    const known = CATEGORY_ORDER.filter((c) => grouped[c]);
    const extra = Object.keys(grouped).filter((c) => !CATEGORY_ORDER.includes(c));
    return [...known, ...extra];
  }, [grouped]);

  const selected = templates.find((t) => t.template_id === templateId);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      if (!templateId) {
        toast.error('Pick a vendor template first');
        return;
      }
      if (hmacEnabled && hmacSecret.trim().length < 16) {
        toast.error('HMAC secret must be at least 16 characters');
        return;
      }
      setSubmitting(true);
      try {
        const secret = await inboxApi.mint({
          template_id: templateId,
          label: label.trim() || null,
          hmac_secret: hmacEnabled ? hmacSecret.trim() : null,
        });
        toast.success(`Minted ${selected?.label ?? templateId} URL`);
        // Reset only after success — preserve form on error so the
        // operator can fix the input without re-typing.
        setLabel('');
        setHmacEnabled(false);
        setHmacSecret('');
        onCreated(secret);
      } catch (err) {
        const msg =
          err instanceof ApiError
            ? err.message
            : err instanceof Error
              ? err.message
              : 'Failed to mint inbox URL';
        toast.error(msg);
      } finally {
        setSubmitting(false);
      }
    },
    [hmacEnabled, hmacSecret, label, onCreated, selected, templateId],
  );

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-gray-800 bg-gray-900/40 p-4 space-y-4"
    >
      <div>
        <label className="block text-xs text-gray-400 mb-1.5">
          Vendor template
        </label>
        <select
          value={templateId}
          onChange={(e) => setTemplateId(e.target.value)}
          className="w-full bg-gray-950 border border-gray-700 rounded-md px-2 py-1.5 text-sm text-gray-100"
        >
          {orderedCategories.map((cat) => (
            <optgroup key={cat} label={categoryLabel(cat)}>
              {grouped[cat].map((t) => (
                <option key={t.template_id} value={t.template_id}>
                  {t.label}
                </option>
              ))}
            </optgroup>
          ))}
        </select>
        {selected && (
          <p className="text-xs text-gray-500 mt-1.5">{selected.description}</p>
        )}
      </div>

      <div>
        <label className="block text-xs text-gray-400 mb-1.5">
          Label (optional)
        </label>
        <input
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="PagerDuty on-call"
          className="w-full bg-gray-950 border border-gray-700 rounded-md px-2 py-1.5 text-sm text-gray-100"
        />
        <p className="text-xs text-gray-500 mt-1">
          Helps you tell tokens apart when the same template is used by
          multiple vendors or environments.
        </p>
      </div>

      <div>
        <label className="flex items-center gap-2 text-xs text-gray-300">
          <input
            type="checkbox"
            checked={hmacEnabled}
            onChange={(e) => setHmacEnabled(e.target.checked)}
            className="accent-blue-500"
          />
          Require HMAC signature on inbound requests
        </label>
        <p className="text-xs text-gray-500 mt-1 pl-6">
          Recommended when the vendor supports it. Without HMAC the URL
          token is the sole authenticator.
        </p>
        {hmacEnabled && (
          <input
            type="password"
            value={hmacSecret}
            onChange={(e) => setHmacSecret(e.target.value)}
            placeholder="Shared secret (≥ 16 chars)"
            className="mt-2 w-full bg-gray-950 border border-gray-700 rounded-md px-2 py-1.5 text-sm text-gray-100 font-mono"
            minLength={16}
            maxLength={512}
          />
        )}
      </div>

      <div className="flex justify-end pt-2 border-t border-gray-800">
        <button
          type="submit"
          disabled={submitting || !templateId}
          className={clsx(
            'text-sm px-4 py-1.5 rounded-md text-white transition-colors',
            submitting || !templateId
              ? 'bg-blue-700/50 cursor-not-allowed'
              : 'bg-blue-600 hover:bg-blue-500',
          )}
        >
          {submitting ? 'Minting…' : 'Mint URL'}
        </button>
      </div>
    </form>
  );
}

// ─── token list ───────────────────────────────────────────────────────────

function TokensTable({
  tokens,
  templates,
  onRotate,
  onRevoke,
  busyFingerprint,
}: {
  tokens: InboxTokenListItem[];
  templates: InboxTemplate[];
  onRotate: (fp: string) => void | Promise<void>;
  onRevoke: (fp: string) => void | Promise<void>;
  busyFingerprint: string | null;
}) {
  const labelFor = (templateId: string): string => {
    return (
      templates.find((t) => t.template_id === templateId)?.label ?? templateId
    );
  };

  if (tokens.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-gray-800 bg-gray-900/30 p-6 text-center">
        <p className="text-sm text-gray-400">No inbox URLs yet.</p>
        <p className="text-xs text-gray-500 mt-1">
          Mint one above to give a vendor a place to push alerts.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/40 overflow-hidden">
      <table className="w-full text-xs">
        <thead className="bg-gray-900/80 text-gray-500 uppercase tracking-wide">
          <tr>
            <th className="text-left px-3 py-2 font-medium">Template</th>
            <th className="text-left px-3 py-2 font-medium">Label</th>
            <th className="text-left px-3 py-2 font-medium">Fingerprint</th>
            <th className="text-left px-3 py-2 font-medium">HMAC</th>
            <th className="text-left px-3 py-2 font-medium">Created</th>
            <th className="text-left px-3 py-2 font-medium">Last used</th>
            <th className="text-right px-3 py-2 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/80">
          {tokens.map((t) => {
            const busy = busyFingerprint === t.fingerprint;
            return (
              <tr key={t.fingerprint} className="text-gray-200">
                <td className="px-3 py-2">{labelFor(t.template_id)}</td>
                <td className="px-3 py-2 text-gray-400">{t.label ?? '—'}</td>
                <td className="px-3 py-2 font-mono text-gray-400">
                  {t.fingerprint}
                </td>
                <td className="px-3 py-2">
                  {t.has_hmac_secret ? (
                    <span className="inline-flex items-center gap-1 text-emerald-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      on
                    </span>
                  ) : (
                    <span className="text-gray-500">off</span>
                  )}
                </td>
                <td className="px-3 py-2 text-gray-400">
                  {formatRelative(t.created_at)}
                </td>
                <td className="px-3 py-2 text-gray-400">
                  {formatRelative(t.last_used_at)}
                </td>
                <td className="px-3 py-2 text-right">
                  <div className="flex justify-end gap-1.5">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => onRotate(t.fingerprint)}
                      className={clsx(
                        'text-xs px-2 py-1 rounded-md',
                        busy
                          ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                          : 'bg-gray-800 hover:bg-gray-700 text-gray-200',
                      )}
                      title="Mint a new token with the same template/label/HMAC and revoke this one"
                    >
                      Rotate
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => onRevoke(t.fingerprint)}
                      className={clsx(
                        'text-xs px-2 py-1 rounded-md',
                        busy
                          ? 'bg-gray-800 text-gray-500 cursor-not-allowed'
                          : 'bg-red-600/20 hover:bg-red-600/30 text-red-300',
                      )}
                      title="Permanently revoke this token. Vendor traffic will be rejected."
                    >
                      Revoke
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ─── outer panel ──────────────────────────────────────────────────────────

/**
 * Top-level panel rendered by the Connectors page.
 *
 * Lazy-loads templates + tokens the first time it expands so the
 * Connectors page stays cheap on initial render. Expansion state is
 * deliberately *not* persisted — operators rarely return to it twice in
 * a session, and a default-collapsed UI keeps the page from feeling
 * busy when the catalog already covers their tools.
 */
export function InboxTokensPanel() {
  const [open, setOpen] = useState<boolean>(false);
  const [templates, setTemplates] = useState<InboxTemplate[]>([]);
  const [tokens, setTokens] = useState<InboxTokenListItem[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busyFingerprint, setBusyFingerprint] = useState<string | null>(null);
  const [disclosed, setDisclosed] = useState<InboxTokenSecret | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [tmpl, toks] = await Promise.all([
        inboxApi.templates(),
        inboxApi.list(),
      ]);
      setTemplates(tmpl);
      setTokens(toks);
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'Failed to load inbox tokens';
      setLoadError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  // Lazy-load only after the operator opens the panel — keeps the
  // Connectors page render cheap when nothing is using universal
  // capture yet.
  useEffect(() => {
    if (open && templates.length === 0 && !loading && !loadError) {
      void refresh();
    }
  }, [loadError, loading, open, refresh, templates.length]);

  const handleCreated = useCallback(
    async (secret: InboxTokenSecret) => {
      setDisclosed(secret);
      // Reload the list in the background so the new fingerprint shows
      // up by the time the disclosure modal closes.
      void refresh();
    },
    [refresh],
  );

  const handleRotate = useCallback(
    async (fingerprint: string) => {
      setBusyFingerprint(fingerprint);
      try {
        const secret = await inboxApi.rotate(fingerprint);
        toast.success('Rotated — copy the new URL before closing');
        setDisclosed(secret);
        await refresh();
      } catch (err) {
        const msg =
          err instanceof ApiError
            ? err.message
            : err instanceof Error
              ? err.message
              : 'Failed to rotate token';
        toast.error(msg);
      } finally {
        setBusyFingerprint(null);
      }
    },
    [refresh],
  );

  const handleRevoke = useCallback(
    async (fingerprint: string) => {
      const ok = window.confirm(
        'Revoke this inbox URL? Vendor traffic to it will be rejected immediately. This cannot be undone — you would need to mint a new URL and reconfigure the vendor.',
      );
      if (!ok) return;

      setBusyFingerprint(fingerprint);
      try {
        await inboxApi.revoke(fingerprint);
        toast.success('Token revoked');
        await refresh();
      } catch (err) {
        const msg =
          err instanceof ApiError
            ? err.message
            : err instanceof Error
              ? err.message
              : 'Failed to revoke token';
        toast.error(msg);
      } finally {
        setBusyFingerprint(null);
      }
    },
    [refresh],
  );

  const activeCount = useMemo(
    () => tokens.filter((t) => t.revoked_at == null).length,
    [tokens],
  );

  return (
    <div className="rounded-xl border border-gray-800/60 bg-gray-900/40">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="w-full flex items-center justify-between px-4 py-3 text-left"
        aria-expanded={open}
      >
        <div className="flex items-center gap-3">
          <span
            className={clsx(
              'inline-flex h-7 w-7 items-center justify-center rounded-md',
              'bg-blue-500/15 text-blue-300',
            )}
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M13 5l7 7-7 7M5 5l7 7-7 7"
              />
            </svg>
          </span>
          <div>
            <h2 className="text-sm font-semibold text-gray-100">
              Universal capture (push)
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Mint webhook URLs for any vendor that can POST JSON, send
              email, or speak CEF/HEC. {open ? '' : `${activeCount} active`}
            </p>
          </div>
        </div>
        <svg
          className={clsx(
            'w-4 h-4 text-gray-500 transition-transform',
            open ? 'rotate-180' : '',
          )}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="inbox-body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-4 border-t border-gray-800/60 pt-4">
              {loadError && (
                <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200">
                  {loadError}{' '}
                  <button
                    type="button"
                    onClick={() => void refresh()}
                    className="underline ml-1 hover:text-amber-100"
                  >
                    Retry
                  </button>
                </div>
              )}
              {loading && templates.length === 0 ? (
                <div className="text-xs text-gray-500 py-4 text-center">
                  Loading…
                </div>
              ) : (
                <>
                  <MintForm
                    templates={templates}
                    onCreated={handleCreated}
                  />
                  <TokensTable
                    tokens={tokens}
                    templates={templates}
                    onRotate={handleRotate}
                    onRevoke={handleRevoke}
                    busyFingerprint={busyFingerprint}
                  />
                </>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {disclosed && (
        <SecretDisclosureModal
          secret={disclosed}
          onClose={() => setDisclosed(null)}
        />
      )}
    </div>
  );
}
