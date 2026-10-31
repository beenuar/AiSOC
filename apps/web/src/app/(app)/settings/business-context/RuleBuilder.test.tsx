/**
 * The builder may only suggest fields that resolve on the fused alert, and
 * only operators the engines implement.
 *
 * The canonical field list is pinned twice — here and in the api suite's
 * `test_rule_vocabulary_resolves.py`, which resolves these same literals
 * against the fused-alert shape through the real engine resolver. Two copies,
 * one assertion each: drift reds one of them.
 *
 * The operator half pins `ne` (the engines' term). The builder used to offer
 * `neq`, which neither engine implements — a "not equals" clause silently
 * never matched.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SOURCE = readFileSync(join(__dirname, 'RuleBuilder.tsx'), 'utf8');

const CANONICAL_FIELDS = [
  'severity',
  'source',
  'hostname',
  'username',
  'src_ip',
  'dst_ip',
  'domain',
  'tags',
  'risk_score',
  'raw_event.env',
];

// services/agents/app/workers/business_context.py::_cmp and
// services/api/app/services/business_context/engine.py::_eval_op.
const ENGINE_OPS = new Set([
  'eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'contains',
  'startswith', 'endswith', 'in', 'not_in', 'exists', 'not_exists',
]);

function extractArray(name: string): string[] {
  const match = SOURCE.match(new RegExp(`const ${name}[^=]*= \\[([^;]*?)\\];`, 's'));
  if (!match) throw new Error(`${name} not found in RuleBuilder.tsx`);
  return [...match[1].matchAll(/["']([^"']+)["']/g)].map((m) => m[1]);
}

describe('RuleBuilder vocabulary', () => {
  it('suggests exactly the canonical fused-alert fields', () => {
    expect(extractArray('FIELD_SUGGESTIONS')).toEqual(CANONICAL_FIELDS);
  });

  it('offers only operators the engines implement', () => {
    const opValues = [...SOURCE.matchAll(/\{ value: ["']([a-z_]+)["'], label:/g)].map((m) => m[1]);
    expect(opValues.length).toBeGreaterThan(0);
    for (const op of opValues) {
      expect(ENGINE_OPS.has(op), `builder offers '${op}' which no engine implements`).toBe(true);
    }
  });

  it('never suggests the dead alert.-prefixed paths', () => {
    for (const field of extractArray('FIELD_SUGGESTIONS')) {
      expect(field.startsWith('alert.')).toBe(false);
    }
  });
});
