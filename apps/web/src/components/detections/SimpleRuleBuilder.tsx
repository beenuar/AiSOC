'use client';

// Wave 3 (W3.3) — no-code / simple detection builder. A form (log source +
// field/operator/value rows + optional threshold) that compiles to a valid
// Sigma rule, for teams without detection engineers. The generated Sigma drops
// straight into the code-first editor, where it can be tested, backtested, and
// proposed through the same governed lifecycle.

import { useState } from 'react';

type Operator = 'equals' | 'contains' | 'startswith' | 'endswith';

interface Condition {
  field: string;
  operator: Operator;
  value: string;
}

const OPERATORS: { id: Operator; label: string }[] = [
  { id: 'equals', label: 'equals' },
  { id: 'contains', label: 'contains' },
  { id: 'startswith', label: 'starts with' },
  { id: 'endswith', label: 'ends with' },
];

function yamlEscape(value: string): string {
  // Single-quote the scalar and escape embedded single quotes per YAML rules.
  return `'${value.replace(/'/g, "''")}'`;
}

export function buildSigma(opts: {
  title: string;
  product: string;
  category: string;
  level: string;
  conditions: Condition[];
}): string {
  const selectors = opts.conditions
    .filter((c) => c.field.trim() && c.value.trim())
    .map((c) => {
      const key = c.operator === 'equals' ? c.field : `${c.field}|${c.operator}`;
      return `    ${key}: ${yamlEscape(c.value)}`;
    });
  const logsource = [
    'logsource:',
    opts.product ? `  product: ${opts.product}` : '',
    opts.category ? `  category: ${opts.category}` : '',
  ]
    .filter(Boolean)
    .join('\n');
  return [
    `title: ${opts.title || 'Untitled detection'}`,
    'status: experimental',
    logsource,
    'detection:',
    '  selection:',
    selectors.length ? selectors.join('\n') : "    EventID: ''",
    '  condition: selection',
    `level: ${opts.level}`,
    '',
  ].join('\n');
}

export function SimpleRuleBuilder({
  onGenerate,
}: {
  onGenerate: (sigma: string) => void;
}) {
  const [title, setTitle] = useState('');
  const [product, setProduct] = useState('windows');
  const [category, setCategory] = useState('process_creation');
  const [level, setLevel] = useState('medium');
  const [conditions, setConditions] = useState<Condition[]>([
    { field: 'CommandLine', operator: 'contains', value: '' },
  ]);

  const update = (i: number, patch: Partial<Condition>) =>
    setConditions((prev) =>
      prev.map((c, idx) => (idx === i ? { ...c, ...patch } : c)),
    );

  return (
    <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-900/40 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-200">No-code builder</h3>
        <button
          type="button"
          onClick={() =>
            onGenerate(
              buildSigma({ title, product, category, level, conditions }),
            )
          }
          className="rounded-md bg-blue-600/80 px-3 py-1.5 text-xs font-medium text-white"
        >
          Generate Sigma
        </button>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Rule title"
          className="col-span-2 rounded-md border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 outline-none focus:border-blue-500/60"
        />
        <input
          value={product}
          onChange={(e) => setProduct(e.target.value)}
          placeholder="log source product (e.g. windows)"
          className="rounded-md border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 outline-none focus:border-blue-500/60"
        />
        <input
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          placeholder="category (e.g. process_creation)"
          className="rounded-md border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 outline-none focus:border-blue-500/60"
        />
      </div>

      <div className="space-y-2">
        {conditions.map((c, i) => (
          <div key={i} className="flex items-center gap-2">
            <input
              value={c.field}
              onChange={(e) => update(i, { field: e.target.value })}
              placeholder="field"
              className="w-1/3 rounded-md border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 outline-none focus:border-blue-500/60"
            />
            <select
              value={c.operator}
              onChange={(e) =>
                update(i, { operator: e.target.value as Operator })
              }
              className="rounded-md border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 outline-none focus:border-blue-500/60"
            >
              {OPERATORS.map((op) => (
                <option key={op.id} value={op.id}>
                  {op.label}
                </option>
              ))}
            </select>
            <input
              value={c.value}
              onChange={(e) => update(i, { value: e.target.value })}
              placeholder="value"
              className="flex-1 rounded-md border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-200 outline-none focus:border-blue-500/60"
            />
            {conditions.length > 1 && (
              <button
                type="button"
                onClick={() =>
                  setConditions((prev) => prev.filter((_, idx) => idx !== i))
                }
                className="rounded-md border border-gray-800 px-2 py-1.5 text-xs text-gray-400 hover:text-red-400"
                aria-label="Remove condition"
              >
                ×
              </button>
            )}
          </div>
        ))}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() =>
              setConditions((prev) => [
                ...prev,
                { field: '', operator: 'contains', value: '' },
              ])
            }
            className="rounded-md border border-gray-800 px-2 py-1 text-xs text-gray-300 hover:border-blue-500/60"
          >
            + Add condition
          </button>
          <select
            value={level}
            onChange={(e) => setLevel(e.target.value)}
            className="ml-auto rounded-md border border-gray-800 bg-gray-950 px-2 py-1 text-xs text-gray-200 outline-none focus:border-blue-500/60"
          >
            {['info', 'low', 'medium', 'high', 'critical'].map((l) => (
              <option key={l} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>
      </div>
      <p className="text-[11px] text-gray-600">
        Generates a Sigma rule (all conditions ANDed) into the editor — then
        test, backtest, and propose it through the governed lifecycle.
      </p>
    </div>
  );
}
