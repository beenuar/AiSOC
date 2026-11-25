'use client';

import { useId, useState } from 'react';
import type { AlertEntityType, AlertFilters } from '@/lib/api';
import { ALERT_ENTITY_LABELS, isAlertEntityType } from '@/lib/alertEntityFilter';

export function EntityAlertFilter({
  filters,
  onChange,
}: {
  filters: AlertFilters;
  onChange: (filters: AlertFilters) => void;
}) {
  const id = useId();
  const [entityType, setEntityType] = useState<AlertEntityType | ''>(filters.entityType ?? '');
  const [entityValue, setEntityValue] = useState(filters.entityValue ?? '');
  const value = entityValue.trim();

  return (
    <form
      aria-label="Filter alerts by entity"
      className="flex w-full flex-wrap items-end gap-3 border-t border-gray-800/60 pt-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (!value || value.length > 2048) return;
        onChange({
          ...filters,
          entityType: entityType || undefined,
          entityValue: value,
          page: 1,
        });
      }}
    >
      <div className="space-y-1">
        <label htmlFor={`${id}-type`} className="block text-xs text-gray-400">Entity type</label>
        <select
          id={`${id}-type`}
          value={entityType}
          onChange={(event) => setEntityType(isAlertEntityType(event.target.value) ? event.target.value : '')}
          className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All types</option>
          {Object.entries(ALERT_ENTITY_LABELS).map(([type, label]) => (
            <option key={type} value={type}>{label}</option>
          ))}
        </select>
      </div>
      <div className="min-w-48 flex-1 space-y-1">
        <label htmlFor={`${id}-value`} className="block text-xs text-gray-400">Entity value</label>
        <input
          id={`${id}-value`}
          value={entityValue}
          onChange={(event) => setEntityValue(event.target.value)}
          maxLength={2048}
          autoComplete="off"
          spellCheck={false}
          placeholder="Hostname, username, IP, domain, asset, or URL"
          aria-describedby={`${id}-hint`}
          className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>
      <button
        type="submit"
        disabled={!value || value.length > 2048}
        className="rounded-lg bg-blue-600 px-3 py-2 text-sm text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
      >
        Apply entity filter
      </button>
      <p id={`${id}-hint`} className="w-full text-xs text-gray-500">
        Exact match, including letter case. Leave the type as All types to search across entity kinds.
      </p>
      {filters.entityValue && (
        <button
          type="button"
          aria-label="Remove entity filter"
          title={filters.entityValue}
          onClick={() => onChange({ ...filters, entityType: undefined, entityValue: undefined, page: 1 })}
          className="max-w-full break-all rounded border border-blue-500/30 bg-blue-500/10 px-2 py-1 text-start text-xs text-blue-300 hover:bg-blue-500/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-blue-400"
        >
          {filters.entityType ? ALERT_ENTITY_LABELS[filters.entityType] : 'Entity'}: {filters.entityValue} ×
        </button>
      )}
    </form>
  );
}
