'use client';

/**
 * Edit a saved connector instance: rename it, change its settings, rotate
 * any of its secrets.
 *
 * The form is built from the same catalog schema the add wizard uses, with
 * two differences that both follow from the API never returning a secret:
 *
 * - **Secret fields start blank and blank means "keep".** The stored value is
 *   vault-encrypted and is not part of `ConnectorResponse`, so there is
 *   nothing to prefill. A blank secret is therefore not sent; a typed one
 *   replaces only that key.
 * - **Only what the operator changed is sent.** `PATCH /connectors/{id}`
 *   merges `auth_config` and `connector_config` one key at a time (a `null`
 *   removes a key), so a save leaves the other secrets, the scheduler's
 *   `checkpoint` and the `filter_rules` stored beside these fields alone.
 *
 * Before this existed the Configure button answered "Delete + re-add", and a
 * re-added connector starts over: a new id, no checkpoint (the first poll
 * re-reads the whole lookback), no event counters, and for push connectors a
 * new ingest token the sender has to be reconfigured with.
 */

import { Fragment, useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import toast from 'react-hot-toast';
import {
  connectorsApi,
  type Connector,
  type ConnectorCatalogEntry,
  type ConnectorSchemaField,
  type UpdateConnectorPayload,
} from '@/lib/api';
import { FieldInput, buildInitialValues, describeApiError } from './AddConnectorModal';

type FormValue = string | number | boolean;
type FormValues = Record<string, FormValue>;

/**
 * Starting form values for a saved instance.
 *
 * Non-secret fields show what is stored; a field the instance has no stored
 * value for shows what the add wizard would have started it on. Secrets
 * always start blank, because the browser is never sent them.
 */
export function buildEditValues(
  fields: ConnectorSchemaField[],
  stored: Record<string, unknown> | undefined,
): FormValues {
  const values = buildInitialValues(fields);
  for (const f of fields) {
    if (f.type === 'secret') continue;
    const v = stored?.[f.name];
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
      values[f.name] = v;
    }
  }
  return values;
}

/**
 * The `auth_config` / `connector_config` halves of the PATCH body: only the
 * fields that differ from where the form started.
 *
 * A cleared optional setting is sent as `null`, which the API reads as
 * "remove this key" — the same state the add wizard leaves an optional field
 * the operator left empty in. A secret is sent only when one was typed.
 */
export function buildConnectorPatch(
  fields: ConnectorSchemaField[],
  initial: FormValues,
  current: FormValues,
): Pick<UpdateConnectorPayload, 'auth_config' | 'connector_config'> {
  const authConfig: Record<string, unknown> = {};
  const connectorConfig: Record<string, unknown> = {};
  for (const f of fields) {
    const v = current[f.name];
    if (f.type === 'secret') {
      if (typeof v === 'string' && v !== '') authConfig[f.name] = v;
      continue;
    }
    if (v === initial[f.name]) continue;
    connectorConfig[f.name] = v === '' ? null : v;
  }
  const patch: Pick<UpdateConnectorPayload, 'auth_config' | 'connector_config'> = {};
  if (Object.keys(authConfig).length > 0) patch.auth_config = authConfig;
  if (Object.keys(connectorConfig).length > 0) patch.connector_config = connectorConfig;
  return patch;
}

/** Labels of required, non-secret fields the operator has emptied. */
export function missingRequiredFields(
  fields: ConnectorSchemaField[],
  values: FormValues,
): string[] {
  return fields
    .filter((f) => f.required && f.type !== 'secret' && values[f.name] === '')
    .map((f) => f.label);
}

interface EditConnectorModalProps {
  /** The instance being edited; `null` keeps the dialog closed. */
  connector: Connector | null;
  onClose: () => void;
  /** Called with the saved row so the parent can refresh its list. */
  onSaved?: (connector: Connector) => void;
}

export function EditConnectorModal({ connector, onClose, onSaved }: EditConnectorModalProps) {
  // Keyed on the id, so opening another instance starts a fresh form while a
  // list refresh — a new object for the same instance — keeps what the
  // operator has typed.
  return (
    <AnimatePresence>
      {connector && (
        <EditConnectorDialog
          key={connector.id}
          connector={connector}
          onClose={onClose}
          onSaved={onSaved}
        />
      )}
    </AnimatePresence>
  );
}

type CatalogState = 'loading' | 'ready' | 'missing' | 'error';

function EditConnectorDialog({
  connector,
  onClose,
  onSaved,
}: EditConnectorModalProps & { connector: Connector }) {
  const [entry, setEntry] = useState<ConnectorCatalogEntry | null>(null);
  const [catalogState, setCatalogState] = useState<CatalogState>('loading');
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [instanceName, setInstanceName] = useState(connector.name);
  const [initialValues, setInitialValues] = useState<FormValues>({});
  const [values, setValues] = useState<FormValues>({});
  const [saving, setSaving] = useState(false);

  // The schema comes from the catalog; the stored settings come from the row
  // the list already holds, so there is no second request for them.
  useEffect(() => {
    let cancelled = false;
    connectorsApi
      .catalog()
      .then((res) => {
        if (cancelled) return;
        const found = res.connectors.find((e) => e.connector_id === connector.type);
        if (!found) {
          setCatalogState('missing');
          return;
        }
        const start = buildEditValues(found.fields, connector.config);
        setEntry(found);
        setInitialValues(start);
        setValues(start);
        setCatalogState('ready');
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setCatalogError(describeApiError(err, 'Failed to load connector catalog'));
        setCatalogState('error');
      });
    return () => {
      cancelled = true;
    };
    // Read once per mounted instance; see the key in `EditConnectorModal`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !saving) onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [saving, onClose]);

  const fields = useMemo(() => entry?.fields ?? [], [entry]);
  const patch = useMemo(
    () => buildConnectorPatch(fields, initialValues, values),
    [fields, initialValues, values],
  );
  const trimmedName = instanceName.trim();
  const nameChanged = trimmedName !== connector.name;
  const dirty = nameChanged || patch.auth_config !== undefined || patch.connector_config !== undefined;

  const handleSave = async () => {
    if (!trimmedName) {
      toast.error('Please give this connector an instance name');
      return;
    }
    const missing = missingRequiredFields(fields, values);
    if (missing.length > 0) {
      toast.error(`Required: ${missing.join(', ')}`);
      return;
    }
    const body: UpdateConnectorPayload = { ...patch };
    if (nameChanged) body.name = trimmedName;

    setSaving(true);
    try {
      const updated = await connectorsApi.update(connector.id, body);
      toast.success(
        body.auth_config
          ? `Saved ${updated.name}. Run Test to check the new credentials.`
          : `Saved ${updated.name}`,
      );
      onSaved?.(updated);
      onClose();
    } catch (err) {
      toast.error(describeApiError(err, 'Failed to save connector'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Fragment>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.15 }}
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
      />

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
          aria-labelledby="edit-connector-title"
          className="pointer-events-auto w-full max-w-2xl max-h-[85vh] overflow-hidden rounded-2xl border border-gray-800 bg-gray-950 shadow-2xl flex flex-col"
        >
          <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-gray-800">
            <div className="min-w-0">
              <h2 id="edit-connector-title" className="text-base font-semibold text-gray-100">
                Edit {connector.name}
              </h2>
              <p className="text-xs text-gray-500 mt-0.5">
                Only the fields you change are saved. Stored credentials are never shown; leave a
                credential blank to keep it.
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              disabled={saving}
              aria-label="Close"
              className="text-gray-500 hover:text-gray-300 transition-colors p-1 disabled:opacity-50"
            >
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
            <div>
              <label
                htmlFor="edit-connector-name"
                className="block text-xs font-semibold text-gray-300 mb-1"
              >
                Instance name
                <span className="text-red-400 ml-0.5">*</span>
              </label>
              <input
                id="edit-connector-name"
                type="text"
                value={instanceName}
                onChange={(e) => setInstanceName(e.target.value)}
                className="w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30"
                required
              />
            </div>

            {catalogState === 'loading' && (
              <div className="flex items-center justify-center h-24 text-gray-600">
                <div className="animate-spin w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full" />
              </div>
            )}

            {catalogState === 'error' && (
              <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                The settings form could not be loaded: {catalogError}. The name can still be
                changed.
              </div>
            )}

            {catalogState === 'missing' && (
              <div className="text-sm text-amber-200 bg-amber-500/10 border border-amber-500/20 rounded-lg p-4">
                This build does not register a <code className="font-mono">{connector.type}</code>{' '}
                connector, so there is no settings form for it. The name can still be changed.
              </div>
            )}

            {catalogState === 'ready' &&
              fields.map((f) => {
                const isSecret = f.type === 'secret';
                const inputId = `edit-connector-field-${f.name}`;
                // A stored secret is kept when its field is left blank, so
                // the input itself is never required here.
                const shown: ConnectorSchemaField = isSecret
                  ? { ...f, required: false, placeholder: 'Stored — leave blank to keep' }
                  : f;
                return (
                  <div key={f.name}>
                    <label htmlFor={inputId} className="block text-xs font-semibold text-gray-300 mb-1">
                      {f.label}
                      {f.required && !isSecret && <span className="text-red-400 ml-0.5">*</span>}
                    </label>
                    <FieldInput
                      id={inputId}
                      field={shown}
                      value={values[f.name]}
                      onChange={(v) => setValues((prev) => ({ ...prev, [f.name]: v }))}
                    />
                    {isSecret && (
                      <p className="mt-1 text-xs text-gray-500">
                        Type a new value to replace the stored one.
                      </p>
                    )}
                    {f.help_text && (
                      <p className="mt-1 text-xs text-gray-500 leading-relaxed">{f.help_text}</p>
                    )}
                  </div>
                );
              })}
          </div>

          <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-gray-800 bg-gray-950/80">
            <button
              type="button"
              onClick={onClose}
              disabled={saving}
              className="text-sm text-gray-400 hover:text-gray-200 px-3 py-2 rounded-lg transition-colors disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={saving || !dirty}
              className="text-sm bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {saving && (
                <span className="animate-spin w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full" />
              )}
              Save changes
            </button>
          </div>
        </div>
      </motion.div>
    </Fragment>
  );
}
