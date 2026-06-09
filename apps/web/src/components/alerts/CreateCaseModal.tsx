'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';
import {
  casesApi,
  type Alert,
  type Case,
  type CaseSeverity,
} from '@/lib/api';

// Alerts carry an extra `info` severity that cases don't model; fold it into
// the lowest case severity so promotion never sends an invalid value.
function alertSeverityToCaseSeverity(severity: Alert['severity']): CaseSeverity {
  return severity === 'info' ? 'low' : severity;
}

type Mode = 'new' | 'existing';

interface CreateCaseModalProps {
  open: boolean;
  onClose: () => void;
  alert: Alert;
}

/**
 * Promotes a single alert into a case (issue #293). Offers two paths in one
 * modal: create a brand-new case seeded from the alert, or attach the alert to
 * an existing open case. On success the analyst is taken straight to the case
 * so they can run a playbook against it.
 */
export function CreateCaseModal({ open, onClose, alert }: CreateCaseModalProps) {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>('new');
  const [title, setTitle] = useState(alert.title ?? '');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>(
    alertSeverityToCaseSeverity(alert.severity),
  );
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Only load the existing-case list once the analyst switches to that tab.
  const { data: openCases, isLoading: casesLoading } = useSWR(
    open && mode === 'existing' ? ['cases-open', 'open'] : null,
    () => casesApi.list({ status: 'open' }),
  );

  if (!open) return null;

  const goToCase = (createdCase: Case) => {
    toast.success(
      mode === 'new'
        ? `Created ${createdCase.caseNumber ?? 'case'} from alert`
        : `Alert added to ${createdCase.caseNumber ?? 'case'}`,
    );
    onClose();
    router.push(`/cases/${createdCase.id}`);
  };

  const handleSubmit = async () => {
    if (submitting) return;

    if (mode === 'new') {
      if (title.trim().length < 3) {
        toast.error('Case title must be at least 3 characters.');
        return;
      }
      setSubmitting(true);
      try {
        const created = await casesApi.create({
          title: title.trim(),
          description: description.trim() || undefined,
          severity,
            alertIds: [alert.id],
            // Seed the case with the alert's MITRE techniques so coverage
            // carries over. `mitreAttack` is the per-alert shape; the case API
            // wants flat technique IDs.
            mitre: alert.mitreAttack?.map((m) => m.techniqueId).filter(Boolean),
        });
        goToCase(created);
      } catch {
        toast.error('Could not create the case. Please try again.');
      } finally {
        setSubmitting(false);
      }
      return;
    }

    // mode === 'existing'
    if (!selectedCaseId) {
      toast.error('Pick a case to add this alert to.');
      return;
    }
    setSubmitting(true);
    try {
      const updated = await casesApi.linkAlerts(selectedCaseId, [alert.id]);
      goToCase(updated);
    } catch {
      toast.error('Could not link the alert. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Create or update case from alert"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-xl border border-gray-800 bg-gray-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
          <h2 className="text-base font-semibold text-white">
            Promote alert to case
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-white"
            aria-label="Close"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="px-5 pt-4">
          <div className="inline-flex rounded-lg bg-gray-800 p-0.5 text-sm">
            <button
              type="button"
              onClick={() => setMode('new')}
              className={clsx(
                'px-3 py-1.5 rounded-md font-medium transition-colors',
                mode === 'new' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:text-white',
              )}
            >
              Create new case
            </button>
            <button
              type="button"
              onClick={() => setMode('existing')}
              className={clsx(
                'px-3 py-1.5 rounded-md font-medium transition-colors',
                mode === 'existing' ? 'bg-blue-600 text-white' : 'text-gray-300 hover:text-white',
              )}
            >
              Add to existing case
            </button>
          </div>
        </div>

        <div className="space-y-4 px-5 py-4">
          {mode === 'new' ? (
            <>
              <div>
                <label htmlFor="case-title" className="mb-1 block text-xs font-medium text-gray-400">
                  Title
                </label>
                <input
                  id="case-title"
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  placeholder="Short case title"
                />
              </div>
              <div>
                <label htmlFor="case-description" className="mb-1 block text-xs font-medium text-gray-400">
                  Description <span className="text-gray-600">(optional)</span>
                </label>
                <textarea
                  id="case-description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={3}
                  className="w-full resize-none rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  placeholder="Why is this alert being promoted?"
                />
              </div>
              <div>
                <label htmlFor="case-severity" className="mb-1 block text-xs font-medium text-gray-400">
                  Severity
                </label>
                <select
                  id="case-severity"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as CaseSeverity)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
            </>
          ) : (
            <div>
              <label htmlFor="case-existing" className="mb-1 block text-xs font-medium text-gray-400">
                Open case
              </label>
              <select
                id="case-existing"
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                disabled={casesLoading}
                className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none disabled:opacity-60"
              >
                <option value="">
                  {casesLoading ? 'Loading cases…' : 'Select a case…'}
                </option>
                {openCases?.cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {(c.caseNumber ? `${c.caseNumber} · ` : '') + c.title}
                  </option>
                ))}
              </select>
              {!casesLoading && openCases && openCases.cases.length === 0 && (
                <p className="mt-2 text-xs text-gray-500">
                  No open cases yet — create a new one instead.
                </p>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-gray-800 px-5 py-4">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm font-medium text-gray-300 hover:text-white"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={submitting}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {submitting
              ? 'Working…'
              : mode === 'new'
                ? 'Create case'
                : 'Add to case'}
          </button>
        </div>
      </div>
    </div>
  );
}
