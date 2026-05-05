'use client';

/**
 * Click-and-connect wizard for adding a new connector instance.
 *
 * Two-step flow:
 *
 * 1. **Catalog picker** — fetches ``GET /api/v1/connectors/catalog`` and
 *    renders one card per registered connector class, grouped by category.
 *    The catalog is the source of truth for which connectors this build
 *    supports; we never ship a hardcoded list in the frontend.
 *
 * 2. **Schema-driven config form** — each catalog entry declares its own
 *    ``fields[]`` (see ``BaseConnector.schema()``), so this component
 *    builds the form dynamically from the selected entry. Field types map
 *    to controls:
 *      - ``string`` / ``number`` → text/number input
 *      - ``secret`` → masked password input
 *      - ``textarea`` → multi-line input (used for pasted JSON keys)
 *      - ``select`` → native ``<select>`` with provided options
 *      - ``boolean`` → checkbox
 *
 * Test-before-save lives on the second screen: it POSTs the cleartext
 * credentials to ``/api/v1/connectors/test`` (which forwards to the
 * stateless connectors microservice) without persisting anything. Only on
 * "Save" does the API encrypt the credentials in the vault and write a
 * row to Postgres.
 *
 * The modal is intentionally a single component file because the wizard
 * state machine is small (catalog → config → done) and splitting it would
 * fragment the form/state coupling for no real reuse benefit.
 */

import { Fragment, useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import {
  connectorsApi,
  type Connector,
  type ConnectorCatalogEntry,
  type ConnectorSchemaField,
  type ConnectorTestResult,
} from '@/lib/api';

// ─── Field rendering helpers ────────────────────────────────────────────────

/**
 * Compute the initial form values for a catalog entry.
 *
 * Defaults from the schema flow into ``connector_config`` so the operator
 * sees them already populated. Secrets always start empty — never seed a
 * default secret, even if the schema were to declare one.
 */
function buildInitialValues(
  fields: ConnectorSchemaField[],
): Record<string, string | number | boolean> {
  const values: Record<string, string | number | boolean> = {};
  for (const f of fields) {
    if (f.type === 'secret') {
      values[f.name] = '';
      continue;
    }
    if (f.default !== undefined && f.default !== null) {
      values[f.name] = f.default as string | number | boolean;
      continue;
    }
    if (f.type === 'boolean') {
      values[f.name] = false;
      continue;
    }
    if (f.type === 'number') {
      values[f.name] = 0;
      continue;
    }
    values[f.name] = '';
  }
  return values;
}

/**
 * Split a flat values dict into ``auth_config`` (secrets) and
 * ``connector_config`` (everything else).
 *
 * The backend expects this split because secrets get encrypted and
 * non-secrets stay plaintext for poll-config readability in the UI.
 */
function partitionFormValues(
  fields: ConnectorSchemaField[],
  values: Record<string, string | number | boolean>,
): { auth_config: Record<string, unknown>; connector_config: Record<string, unknown> } {
  const auth_config: Record<string, unknown> = {};
  const connector_config: Record<string, unknown> = {};
  for (const f of fields) {
    const v = values[f.name];
    // Empty optional fields are omitted entirely so the backend doesn't
    // need to disambiguate between "operator typed empty string" and
    // "operator did not provide".
    const isEmpty = v === '' || v === null || v === undefined;
    if (isEmpty && !f.required) continue;
    if (f.type === 'secret') {
      auth_config[f.name] = v;
    } else {
      connector_config[f.name] = v;
    }
  }
  return { auth_config, connector_config };
}

interface FieldInputProps {
  field: ConnectorSchemaField;
  value: string | number | boolean;
  onChange: (next: string | number | boolean) => void;
}

function FieldInput({ field, value, onChange }: FieldInputProps) {
  const baseClass =
    'w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30 transition-colors';

  switch (field.type) {
    case 'secret':
      return (
        <input
          type="password"
          autoComplete="new-password"
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder ?? '••••••••'}
          className={clsx(baseClass, 'font-mono')}
          required={field.required}
        />
      );
    case 'textarea':
      return (
        <textarea
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={6}
          className={clsx(baseClass, 'font-mono text-xs resize-y min-h-[120px]')}
          required={field.required}
        />
      );
    case 'select':
      return (
        <select
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          className={baseClass}
          required={field.required}
        >
          {!field.required && <option value="">— none —</option>}
          {(field.options ?? []).map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      );
    case 'boolean':
      return (
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(e) => onChange(e.target.checked)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-500 focus:ring-blue-500/30"
          />
          <span className="text-sm text-gray-300">{field.placeholder ?? 'Enabled'}</span>
        </label>
      );
    case 'number':
      return (
        <input
          type="number"
          value={typeof value === 'number' ? value : Number(value ?? 0)}
          onChange={(e) => {
            const parsed = e.target.value === '' ? 0 : Number(e.target.value);
            onChange(Number.isNaN(parsed) ? 0 : parsed);
          }}
          placeholder={field.placeholder}
          className={baseClass}
          required={field.required}
        />
      );
    case 'string':
    default:
      return (
        <input
          type="text"
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className={baseClass}
          required={field.required}
        />
      );
  }
}

// ─── Catalog grid ────────────────────────────────────────────────────────────

const CATEGORY_ORDER: string[] = [
  'edr',
  'siem',
  'cloud',
  'iam',
  'saas',
  'vcs',
  'network',
];

const CATEGORY_LABEL: Record<string, string> = {
  edr: 'Endpoint',
  siem: 'SIEM',
  cloud: 'Cloud',
  iam: 'Identity',
  saas: 'SaaS',
  vcs: 'Source Control',
  network: 'Network',
};

function CatalogGrid({
  entries,
  onPick,
}: {
  entries: ConnectorCatalogEntry[];
  onPick: (entry: ConnectorCatalogEntry) => void;
}) {
  const grouped = useMemo(() => {
    const groups: Record<string, ConnectorCatalogEntry[]> = {};
    for (const e of entries) {
      const cat = e.category || 'other';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(e);
    }
    // Stable sort by display order, with unknown categories appended.
    const ordered = [...CATEGORY_ORDER.filter((c) => groups[c]), ...Object.keys(groups).filter((c) => !CATEGORY_ORDER.includes(c))];
    return ordered.map((c) => ({ category: c, entries: groups[c] }));
  }, [entries]);

  if (entries.length === 0) {
    return (
      <div className="text-center text-sm text-gray-500 py-12">
        No connector types are registered in this build.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {grouped.map(({ category, entries: groupEntries }) => (
        <section key={category} aria-labelledby={`cat-${category}`}>
          <h3
            id={`cat-${category}`}
            className="text-[11px] uppercase tracking-wider text-gray-500 font-semibold mb-2"
          >
            {CATEGORY_LABEL[category] ?? category}
          </h3>
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
            {groupEntries.map((entry) => (
              <button
                key={entry.connector_id}
                type="button"
                onClick={() => onPick(entry)}
                className="text-left rounded-lg border border-gray-800/80 bg-gray-900/40 hover:bg-gray-900/80 hover:border-gray-700 transition-colors p-4 group"
              >
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="text-sm font-medium text-gray-100 group-hover:text-white">
                    {entry.connector_name}
                  </span>
                  {entry.oauth?.supported_in_hosted && (
                    <span className="text-[10px] uppercase tracking-wider text-amber-300/80 bg-amber-500/10 border border-amber-500/20 rounded px-1.5 py-0.5">
                      OAuth soon
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-500 line-clamp-2">{entry.description}</p>
                <p className="mt-2 text-[11px] text-gray-600 font-mono">{entry.connector_id}</p>
              </button>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

// ─── Config step ─────────────────────────────────────────────────────────────

interface ConfigStepProps {
  entry: ConnectorCatalogEntry;
  values: Record<string, string | number | boolean>;
  setValues: (next: Record<string, string | number | boolean>) => void;
  instanceName: string;
  setInstanceName: (next: string) => void;
}

function ConfigStep({
  entry,
  values,
  setValues,
  instanceName,
  setInstanceName,
}: ConfigStepProps) {
  const updateField = (name: string, next: string | number | boolean) => {
    setValues({ ...values, [name]: next });
  };

  return (
    <div className="space-y-5">
      {/* Friendly label for this instance — separate from the catalog name
          so an operator can have e.g. two CrowdStrike tenants distinguished
          by "Falcon — production" / "Falcon — staging". */}
      <div>
        <label className="block text-xs font-semibold text-gray-300 mb-1">
          Instance name
          <span className="text-red-400 ml-0.5">*</span>
        </label>
        <input
          type="text"
          value={instanceName}
          onChange={(e) => setInstanceName(e.target.value)}
          placeholder={`${entry.connector_name} — production`}
          className="w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30"
          required
        />
        <p className="mt-1 text-xs text-gray-500">
          Shown in the connectors list and on alerts ingested through this connector.
        </p>
      </div>

      {entry.fields.map((f) => (
        <div key={f.name}>
          <label className="block text-xs font-semibold text-gray-300 mb-1">
            {f.label}
            {f.required && <span className="text-red-400 ml-0.5">*</span>}
          </label>
          <FieldInput field={f} value={values[f.name]} onChange={(v) => updateField(f.name, v)} />
          {f.help_text && (
            <p className="mt-1 text-xs text-gray-500 leading-relaxed">{f.help_text}</p>
          )}
        </div>
      ))}

      {entry.docs_url && (
        <p className="text-xs text-gray-500">
          Need help?{' '}
          <a
            href={entry.docs_url}
            target="_blank"
            rel="noreferrer"
            className="text-blue-400 hover:text-blue-300 underline-offset-2 hover:underline"
          >
            View setup guide
          </a>
        </p>
      )}
    </div>
  );
}

// ─── Main modal ──────────────────────────────────────────────────────────────

interface AddConnectorModalProps {
  open: boolean;
  onClose: () => void;
  /** Called after a connector is created so the parent can refresh its list. */
  onCreated?: (connector: Connector) => void;
}

type WizardStep = 'pick' | 'configure';

export function AddConnectorModal({ open, onClose, onCreated }: AddConnectorModalProps) {
  const [step, setStep] = useState<WizardStep>('pick');
  const [catalog, setCatalog] = useState<ConnectorCatalogEntry[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);

  const [selected, setSelected] = useState<ConnectorCatalogEntry | null>(null);
  const [values, setValues] = useState<Record<string, string | number | boolean>>({});
  const [instanceName, setInstanceName] = useState<string>('');

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<ConnectorTestResult | null>(null);
  const [saving, setSaving] = useState(false);

  // Load catalog whenever the modal opens. We don't keep stale data around
  // between opens because the operator may have added a new connector class
  // and redeployed.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setCatalog(null);
    setCatalogError(null);
    setStep('pick');
    setSelected(null);
    setValues({});
    setInstanceName('');
    setTestResult(null);

    connectorsApi
      .catalog()
      .then((res) => {
        if (cancelled) return;
        setCatalog(res.connectors);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : 'Failed to load connector catalog';
        setCatalogError(msg);
      });

    return () => {
      cancelled = true;
    };
  }, [open]);

  // Close on Escape — but only when we're on the picker. On the config
  // screen, prefer the explicit Cancel button so a misclick doesn't lose
  // the operator's typed credentials.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && step === 'pick') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, step, onClose]);

  const handlePick = (entry: ConnectorCatalogEntry) => {
    setSelected(entry);
    setValues(buildInitialValues(entry.fields));
    setInstanceName(entry.connector_name);
    setTestResult(null);
    setStep('configure');
  };

  const handleBack = () => {
    setStep('pick');
    setSelected(null);
    setTestResult(null);
  };

  const handleTest = async () => {
    if (!selected) return;
    setTesting(true);
    setTestResult(null);
    try {
      const { auth_config, connector_config } = partitionFormValues(selected.fields, values);
      const result = await connectorsApi.testInline({
        connector_type: selected.connector_id,
        auth_config,
        connector_config,
      });
      setTestResult(result);
      if (result.success) {
        toast.success('Connection test passed');
      } else {
        toast.error(result.error ?? result.message ?? 'Connection test failed');
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Test request failed';
      setTestResult({ success: false, error: msg });
      toast.error(msg);
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!selected) return;
    if (!instanceName.trim()) {
      toast.error('Please give this connector an instance name');
      return;
    }
    setSaving(true);
    try {
      const { auth_config, connector_config } = partitionFormValues(selected.fields, values);
      const created = await connectorsApi.create({
        name: instanceName.trim(),
        connector_type: selected.connector_id,
        category: selected.category,
        auth_config,
        connector_config,
      });
      toast.success(`Connected ${created.name}`);
      onCreated?.(created);
      onClose();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to save connector';
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  return (
    <AnimatePresence>
      {open && (
        <Fragment>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            onClick={() => {
              if (step === 'pick') onClose();
            }}
          />

          {/* Panel */}
          <motion.div
            initial={{ opacity: 0, y: 12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.98 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none"
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="add-connector-title"
              className="pointer-events-auto w-full max-w-3xl max-h-[85vh] overflow-hidden rounded-2xl border border-gray-800 bg-gray-950 shadow-2xl flex flex-col"
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-gray-800">
                <div>
                  <h2
                    id="add-connector-title"
                    className="text-base font-semibold text-gray-100"
                  >
                    {step === 'pick' ? 'Add connector' : `Configure ${selected?.connector_name ?? ''}`}
                  </h2>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {step === 'pick'
                      ? 'Pick a security tool to connect. Credentials are encrypted with the AiSOC vault.'
                      : 'Credentials are tested against the upstream API and only saved on success.'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onClose}
                  aria-label="Close"
                  className="text-gray-500 hover:text-gray-300 transition-colors p-1"
                >
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Body */}
              <div className="flex-1 overflow-y-auto px-6 py-5">
                {step === 'pick' &&
                  (catalog === null && !catalogError ? (
                    <div className="flex items-center justify-center h-32 text-gray-600">
                      <div className="animate-spin w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full" />
                    </div>
                  ) : catalogError ? (
                    <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                      Failed to load connector catalog: {catalogError}
                    </div>
                  ) : (
                    <CatalogGrid entries={catalog ?? []} onPick={handlePick} />
                  ))}

                {step === 'configure' && selected && (
                  <ConfigStep
                    entry={selected}
                    values={values}
                    setValues={setValues}
                    instanceName={instanceName}
                    setInstanceName={setInstanceName}
                  />
                )}
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between gap-3 px-6 py-4 border-t border-gray-800 bg-gray-950/80">
                {step === 'pick' ? (
                  <>
                    <p className="text-xs text-gray-600">
                      {(catalog?.length ?? 0)} connector type
                      {(catalog?.length ?? 0) === 1 ? '' : 's'} available
                    </p>
                    <button
                      type="button"
                      onClick={onClose}
                      className="text-sm text-gray-400 hover:text-gray-200 px-3 py-2 rounded-lg transition-colors"
                    >
                      Cancel
                    </button>
                  </>
                ) : (
                  <>
                    <div className="flex items-center gap-2 min-w-0">
                      <button
                        type="button"
                        onClick={handleBack}
                        disabled={saving}
                        className="text-sm text-gray-400 hover:text-gray-200 px-3 py-2 rounded-lg transition-colors disabled:opacity-50"
                      >
                        ← Back
                      </button>
                      {testResult && (
                        <span
                          className={clsx(
                            'truncate text-xs px-2 py-1 rounded-md border',
                            testResult.success
                              ? 'text-green-300 bg-green-500/10 border-green-500/20'
                              : 'text-red-300 bg-red-500/10 border-red-500/20',
                          )}
                          title={testResult.message ?? testResult.error ?? ''}
                        >
                          {testResult.success
                            ? testResult.message ?? 'Connection successful'
                            : testResult.error ?? testResult.message ?? 'Connection failed'}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleTest}
                        disabled={testing || saving}
                        className="text-sm bg-gray-800 hover:bg-gray-700 text-gray-200 px-3 py-2 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
                      >
                        {testing && (
                          <span className="animate-spin w-3.5 h-3.5 border-2 border-blue-400 border-t-transparent rounded-full" />
                        )}
                        Test connection
                      </button>
                      <button
                        type="button"
                        onClick={handleSave}
                        disabled={saving || testing}
                        className="text-sm bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
                      >
                        {saving && (
                          <span className="animate-spin w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full" />
                        )}
                        Save connector
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          </motion.div>
        </Fragment>
      )}
    </AnimatePresence>
  );
}
