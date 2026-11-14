'use client';

/**
 * SchemaForm
 * ==========
 *
 * Renders a typed form for a step's `params` object based on a `StepSchema`
 * descriptor. Replaces the old free-form JSON textarea so users can no
 * longer ship malformed playbooks (the canonical failure mode pre-WS-F4).
 *
 * Each field knows its kind (string, number, boolean, select, env-ref,
 * jsonpath, textarea, string-list) and renders the matching control. Unknown
 * keys already present in `params` are surfaced under an "Advanced (raw
 * JSON)" disclosure so power-users can still edit anything the schema does
 * not model.
 *
 * Accessibility
 * -------------
 * Every control carries an `id`, its label a matching `htmlFor`, and its help
 * text and error are referenced through `aria-describedby`. The labels used
 * to be `<label>` elements sitting next to their inputs with no association
 * at all, so a screen reader announced "edit text, blank" for all four fields
 * on a notify step, and the required marker was an `aria-hidden` asterisk
 * conveying requiredness to sighted users only. Errors are now reported per
 * field as well as in the summary, because a list at the bottom of a form
 * saying "Duration is required" does not tell you which control to move to.
 */

import React, { useId, useMemo, useState } from 'react';
import type { FieldDescriptor, StepParamError, StepSchema } from './stepSchemas';

interface SchemaFormProps {
  schema: StepSchema;
  value: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  readOnly?: boolean;
  validationErrors?: readonly StepParamError[];
}

interface ControlProps {
  field: FieldDescriptor;
  id: string;
  value: unknown;
  onChange: (v: unknown) => void;
  readOnly: boolean;
  describedBy?: string;
  invalid: boolean;
}

function renderControl({
  field,
  id,
  value,
  onChange,
  readOnly,
  describedBy,
  invalid,
}: ControlProps): React.ReactNode {
  const baseClass =
    'w-full bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-white text-sm focus:outline-none focus:border-blue-500 disabled:opacity-60';
  const shared = {
    id,
    disabled: readOnly,
    'aria-describedby': describedBy,
    'aria-required': field.required || undefined,
    'aria-invalid': invalid || undefined,
  } as const;

  switch (field.kind) {
    case 'textarea':
      return (
        <textarea
          {...shared}
          rows={4}
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value)}
          className={`${baseClass} font-mono text-xs`}
        />
      );
    case 'number':
      return (
        <input
          {...shared}
          type="number"
          placeholder={field.placeholder}
          value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => {
            const raw = e.target.value;
            if (raw === '') {
              onChange(undefined);
            } else {
              const n = Number(raw);
              onChange(Number.isFinite(n) ? n : raw);
            }
          }}
          className={baseClass}
        />
      );
    case 'boolean':
      return (
        <input
          {...shared}
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(e.target.checked)}
        />
      );
    case 'select':
      return (
        <select
          {...shared}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          className={baseClass}
        >
          <option value="">— select —</option>
          {field.options?.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      );
    case 'string_list':
      // Stored as an array because that is what the handler reads; edited as
      // a comma-separated line because a repeating-row control for two
      // hostnames is more chrome than it is worth.
      return (
        <input
          {...shared}
          type="text"
          placeholder={field.placeholder}
          value={Array.isArray(value) ? value.join(', ') : typeof value === 'string' ? value : ''}
          onChange={(e) => {
            const parts = e.target.value
              .split(',')
              .map((part) => part.trim())
              .filter(Boolean);
            onChange(parts.length ? parts : undefined);
          }}
          className={`${baseClass} font-mono`}
        />
      );
    case 'env_ref':
    case 'jsonpath':
      return (
        <input
          {...shared}
          type="text"
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          className={`${baseClass} font-mono`}
        />
      );
    case 'string':
    default:
      return (
        <input
          {...shared}
          type="text"
          placeholder={field.placeholder}
          value={typeof value === 'string' ? value : ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          className={baseClass}
        />
      );
  }
}

export function SchemaForm({
  schema,
  value,
  onChange,
  readOnly = false,
  validationErrors,
}: SchemaFormProps) {
  const formId = useId();
  const knownKeys = useMemo(
    () => new Set(schema.fields.map((f) => f.key)),
    [schema],
  );
  const extraKeys = useMemo(
    () => Object.keys(value).filter((k) => !knownKeys.has(k)),
    [value, knownKeys],
  );
  const errorsByKey = useMemo(() => {
    const byKey = new Map<string, string[]>();
    for (const error of validationErrors ?? []) {
      if (!error.key) continue;
      byKey.set(error.key, [...(byKey.get(error.key) ?? []), error.message]);
    }
    return byKey;
  }, [validationErrors]);
  const stepLevelErrors = (validationErrors ?? []).filter((e) => !e.key);

  const [showRaw, setShowRaw] = useState(false);
  const [rawDraft, setRawDraft] = useState<string>(() =>
    JSON.stringify(value, null, 2),
  );
  const [rawError, setRawError] = useState<string | null>(null);

  function setField(key: string, next: unknown) {
    if (next === undefined) {
      // Drop the key entirely so we don't persist `undefined`s into JSON.
      const { [key]: _drop, ...rest } = value;
      onChange(rest);
    } else {
      onChange({ ...value, [key]: next });
    }
  }

  if (schema.fields.length === 0 && extraKeys.length === 0) {
    return (
      <div className="space-y-2">
        <p className="text-xs text-gray-500 italic">
          {schema.type === 'condition'
            ? 'Conditions have no params — configure the predicate via the Condition section above.'
            : 'No parameters for this step type.'}
        </p>
        {stepLevelErrors.length > 0 && (
          // `role="alert"` on the wrapper, not on the list: the role replaces
          // the element's own semantics, so a `<ul role="alert">` stops being
          // a list and its `<li>` children are left without a list parent.
          <div role="alert" className="text-xs text-red-400">
            <ul className="space-y-1">
              {stepLevelErrors.map((error) => (
                <li key={error.message}>{error.message}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {schema.fields.map((field) => {
        const controlId = `${formId}-${field.key}`;
        const helpId = field.help ? `${controlId}-help` : undefined;
        const fieldErrors = errorsByKey.get(field.key) ?? [];
        const errorId = fieldErrors.length ? `${controlId}-error` : undefined;
        const describedBy =
          [errorId, helpId].filter(Boolean).join(' ') || undefined;

        return (
          <div key={field.key}>
            <label
              htmlFor={controlId}
              className="block text-gray-400 text-xs mb-1"
            >
              {field.label}
              {field.required && (
                // Spelled out rather than a bare asterisk: the marker is the
                // only cue a non-sighted user gets from the label text, and
                // `aria-required` on the control alone is not announced by
                // every combination of browser and screen reader.
                <span className="text-red-400 ml-1">(required)</span>
              )}
            </label>
            {renderControl({
              field,
              id: controlId,
              value: value[field.key],
              onChange: (v) => setField(field.key, v),
              readOnly,
              describedBy,
              invalid: fieldErrors.length > 0,
            })}
            {fieldErrors.length > 0 && (
              <p id={errorId} className="text-[11px] text-red-400 mt-1">
                {fieldErrors.join(' ')}
              </p>
            )}
            {field.help && (
              <p id={helpId} className="text-[11px] text-gray-500 mt-1">
                {field.help}
              </p>
            )}
          </div>
        );
      })}

      {validationErrors && validationErrors.length > 0 && (
        <div
          role="alert"
          className="text-xs text-red-400 bg-red-950/30 border border-red-900 rounded p-2"
        >
          <ul className="space-y-1">
            {validationErrors.map((error) => (
              <li key={`${error.key ?? ''}:${error.message}`}>• {error.message}</li>
            ))}
          </ul>
        </div>
      )}

      {extraKeys.length > 0 && (
        <div className="text-xs text-amber-400 bg-amber-950/20 border border-amber-900/60 rounded p-2">
          Extra params present that the schema does not model:{' '}
          <code className="font-mono">{extraKeys.join(', ')}</code>. They will
          be preserved on save.
        </div>
      )}

      {/* Raw JSON escape hatch */}
      <div className="border-t border-gray-800 pt-3">
        <button
          type="button"
          aria-expanded={showRaw}
          aria-controls={`${formId}-raw`}
          onClick={() => {
            setRawDraft(JSON.stringify(value, null, 2));
            setRawError(null);
            setShowRaw((v) => !v);
          }}
          className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
        >
          {showRaw ? '▾' : '▸'} Advanced (raw JSON)
        </button>
        {showRaw && (
          <div className="mt-2" id={`${formId}-raw`}>
            <label htmlFor={`${formId}-raw-input`} className="sr-only">
              Raw step parameters as JSON
            </label>
            <textarea
              id={`${formId}-raw-input`}
              rows={6}
              value={rawDraft}
              aria-invalid={rawError ? true : undefined}
              aria-describedby={rawError ? `${formId}-raw-error` : undefined}
              onChange={(e) => {
                setRawDraft(e.target.value);
                try {
                  const parsed = JSON.parse(e.target.value);
                  if (
                    typeof parsed !== 'object' ||
                    parsed === null ||
                    Array.isArray(parsed)
                  ) {
                    setRawError('Params must be a JSON object.');
                    return;
                  }
                  setRawError(null);
                  onChange(parsed as Record<string, unknown>);
                } catch (err) {
                  setRawError(
                    err instanceof Error ? err.message : 'Invalid JSON',
                  );
                }
              }}
              disabled={readOnly}
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-green-400 font-mono text-xs focus:outline-none focus:border-blue-500 disabled:opacity-60"
            />
            {rawError && (
              <p id={`${formId}-raw-error`} className="text-xs text-red-400 mt-1">
                {rawError}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
