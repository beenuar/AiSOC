/**
 * What the connector wizard submits has to be what the operator is looking at.
 *
 * Issue #1685. A required `select` with no schema default started on `''`,
 * while the browser rendered its first `<option>` as chosen — required
 * selects get no blank placeholder. `onChange` fires only on a *change*, so
 * leaving (or re-picking) the option already on screen submitted `''`. For
 * `cloudflare_zt` that meant `mode=''`, and Test connection answered
 * `API 502` with the real reason discarded.
 *
 * The invariant is the last test here, and it is the one that would have
 * caught the bug without anyone having to think of the case: whatever a
 * required select starts on must be a value that select can actually submit.
 */

import { describe, expect, it } from 'vitest';
import { buildInitialValues } from './AddConnectorModal';
import type { ConnectorSchemaField } from '@/lib/api';

function field(over: Partial<ConnectorSchemaField>): ConnectorSchemaField {
  return {
    name: 'f',
    type: 'string',
    label: 'F',
    required: true,
    ...over,
  } as ConnectorSchemaField;
}

const MODE = field({
  name: 'mode',
  type: 'select',
  label: 'Event stream',
  required: true,
  options: [
    { value: 'waf', label: 'WAF / firewall events' },
    { value: 'access', label: 'Zero Trust Access audit' },
  ],
});

describe('buildInitialValues', () => {
  it('starts a required select on its first option, because that is what the browser shows', () => {
    expect(buildInitialValues([MODE]).mode).toBe('waf');
  });

  it('still prefers an explicit schema default over the first option', () => {
    const withDefault = { ...MODE, default: 'access' } as ConnectorSchemaField;
    expect(buildInitialValues([withDefault]).mode).toBe('access');
  });

  it('leaves an optional select empty, so its "— none —" placeholder is the selection', () => {
    const optional = { ...MODE, required: false } as ConnectorSchemaField;
    expect(buildInitialValues([optional]).mode).toBe('');
  });

  it('leaves a required select with no options empty rather than inventing one', () => {
    const empty = { ...MODE, options: [] } as ConnectorSchemaField;
    expect(buildInitialValues([empty]).mode).toBe('');
  });

  it('never seeds a secret, even where one carries a default', () => {
    const secret = field({ name: 'api_token', type: 'secret', default: 'do-not-use' });
    expect(buildInitialValues([secret]).api_token).toBe('');
  });

  it('leaves the other field types where they were', () => {
    const values = buildInitialValues([
      field({ name: 's', type: 'string' }),
      field({ name: 'b', type: 'boolean' }),
      field({ name: 'n', type: 'number' }),
    ]);
    expect(values).toEqual({ s: '', b: false, n: 0 });
  });

  /**
   * The general statement of the defect. A required select renders no blank
   * option, so any starting value that is not one of its options is a value
   * the control cannot display and the operator cannot see — and it is
   * submitted the moment they do not touch the field.
   */
  it('starts every required select on a value that select could submit', () => {
    const fields = [
      MODE,
      field({
        name: 'region',
        type: 'select',
        required: true,
        options: [{ value: 'eu', label: 'EU' }],
      }),
      field({ name: 'tier', type: 'select', required: true, default: 'gold', options: [{ value: 'gold', label: 'Gold' }] }),
    ];
    const values = buildInitialValues(fields);
    for (const f of fields) {
      const allowed = (f.options ?? []).map((o) => o.value);
      expect(allowed, `${f.name} has no options to start on`).not.toHaveLength(0);
      expect(allowed, `${f.name} starts on "${values[f.name]}", which it cannot display`).toContain(values[f.name]);
    }
  });
});
