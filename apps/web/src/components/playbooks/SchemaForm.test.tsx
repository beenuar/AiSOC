/**
 * SchemaForm + stepSchemas — component & validator tests
 * ======================================================
 *
 * Locks in the user-visible behaviour of the JSON-schema-driven form that
 * replaced the old free-text params textarea (WS-F4). The two surfaces
 * exercised here:
 *
 *   1. The form renders the right control for each field kind, lifts edits
 *      via `onChange`, surfaces validation errors, exposes the raw-JSON
 *      escape hatch, and warns about extra params not modelled by the
 *      schema. It must also remain editable in non-readOnly mode and lock
 *      down inputs when readOnly is set.
 *
 *   2. The companion `validateStepParams` helper returns the human
 *      messages the inspector renders. Notify is the trickiest case
 *      because it has channel-conditional required fields.
 */

import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { SchemaForm } from './SchemaForm';

/**
 * Tiny harness that round-trips `value`/`onChange` so the controlled inputs
 * can actually accumulate characters. Without this the parent never updates
 * `value`, React snaps the input back to '' after each keystroke, and
 * "type 900" reduces to "type 0".
 */
function ControlledForm(props: {
  schema: import('./stepSchemas').StepSchema;
  initial?: Record<string, unknown>;
  onChange?: (next: Record<string, unknown>) => void;
}) {
  const [v, setV] = useState<Record<string, unknown>>(props.initial ?? {});
  return (
    <SchemaForm
      schema={props.schema}
      value={v}
      onChange={(next) => {
        setV(next);
        props.onChange?.(next);
      }}
    />
  );
}
import {
  STEP_SCHEMAS,
  defaultParamsFor,
  validateStepParams,
} from './stepSchemas';

describe('SchemaForm — rendering', () => {
  it('marks required fields as required on the control, not just visually', () => {
    const onChange = vi.fn();
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.block_ip}
        value={{}}
        onChange={onChange}
      />,
    );

    // Both fields on block_ip are required. Found by label, which also
    // asserts the label is associated with its control — it used to be a
    // `<label>` sitting next to the input with no `htmlFor`, so a screen
    // reader announced an unnamed text box.
    for (const label of [/IP address field/i, /Duration \(seconds\)/i]) {
      const control = screen.getByLabelText(label);
      expect(control).toBeInTheDocument();
      // The requiredness has to reach assistive technology. An `aria-hidden`
      // asterisk is a cue for sighted users only.
      expect(control).toHaveAttribute('aria-required', 'true');
    }
  });

  it('renders a select with the configured options', () => {
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.notify}
        value={{}}
        onChange={vi.fn()}
      />,
    );

    expect(
      screen.getByRole('option', { name: /Slack/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('option', { name: /PagerDuty/i }),
    ).toBeInTheDocument();
  });

  it('renders a placeholder prompt for an empty short-help block when no params', () => {
    // Use condition (zero-field schema) and no extra keys — should fall
    // through to the short helper string.
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.condition}
        value={{}}
        onChange={vi.fn()}
      />,
    );
    expect(
      screen.getByText(/configure the predicate via the Condition section/i),
    ).toBeInTheDocument();
  });

  it('shows validation errors when supplied', () => {
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.block_ip}
        value={{}}
        onChange={vi.fn()}
        validationErrors={[
          { key: 'ip_field', message: 'IP address field is required.' },
        ]}
      />,
    );
    expect(
      screen.getByRole('alert'),
    ).toHaveTextContent(/IP address field is required/i);
    // The error is also reachable from the control it belongs to, which a
    // summary list at the foot of the form is not.
    expect(screen.getByLabelText(/IP address field/i)).toHaveAccessibleDescription(
      /IP address field is required/i,
    );
  });

  it('warns about extra params not modelled by the schema', () => {
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.enrich}
        value={{ indicator_field: 'alert.src_ip', mystery_param: 'kept' }}
        onChange={vi.fn()}
      />,
    );
    expect(
      screen.getByText(/Extra params present that the schema does not model/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/mystery_param/)).toBeInTheDocument();
  });
});

describe('SchemaForm — interaction', () => {
  it('lifts a string field edit through onChange', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.enrich}
        value={{}}
        onChange={onChange}
      />,
    );

    const input = screen.getByPlaceholderText('alert.src_ip');
    await user.type(input, 'a');

    expect(onChange).toHaveBeenLastCalledWith({ indicator_field: 'a' });
  });

  it('lifts a select change through onChange with the option value', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.notify}
        value={{}}
        onChange={onChange}
      />,
    );

    // The first select on notify is `channel`.
    const channel = screen.getAllByRole('combobox')[0];
    await user.selectOptions(channel, 'pagerduty');

    expect(onChange).toHaveBeenLastCalledWith({ channel: 'pagerduty' });
  });

  it('drops a key entirely when its value clears to empty string', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.create_ticket}
        value={{ queue: 'soc' }}
        onChange={onChange}
      />,
    );

    const queueInput = screen.getByPlaceholderText('soc');
    await user.clear(queueInput);

    // Last call should have stripped `queue` entirely.
    const lastCall = onChange.mock.calls.at(-1)![0] as Record<string, unknown>;
    expect('queue' in lastCall).toBe(false);
  });

  it('coerces number fields to numeric values', () => {
    const onChange = vi.fn();
    render(
      <ControlledForm schema={STEP_SCHEMAS.block_ip} onChange={onChange} />,
    );

    const dur = screen.getByRole('spinbutton');
    // Use fireEvent.change so we set the controlled value in one shot rather
    // than relying on character-by-character input synthesis (which fights
    // with the controlled input round-trip).
    fireEvent.change(dur, { target: { value: '900' } });

    const last = onChange.mock.calls.at(-1)![0] as Record<string, unknown>;
    expect(typeof last.duration).toBe('number');
    expect(last.duration).toBe(900);
  });

  it('clears a number field back to undefined when emptied', () => {
    const onChange = vi.fn();
    render(
      <ControlledForm
        schema={STEP_SCHEMAS.block_ip}
        initial={{ duration: 60 }}
        onChange={onChange}
      />,
    );

    const dur = screen.getByRole('spinbutton');
    fireEvent.change(dur, { target: { value: '' } });

    const last = onChange.mock.calls.at(-1)![0] as Record<string, unknown>;
    // The field is dropped from the params object entirely.
    expect('duration' in last).toBe(false);
  });

  it('disables every control when readOnly is true', () => {
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.block_ip}
        value={{ ip_field: 'alert.src_ip', duration: 60 }}
        onChange={vi.fn()}
        readOnly
      />,
    );

    const inputs = [
      ...screen.getAllByRole('textbox', { hidden: true }),
      ...screen.getAllByRole('spinbutton', { hidden: true }),
    ];
    inputs.forEach((el) => {
      expect(el).toBeDisabled();
    });
  });

  it('opens the raw JSON escape hatch on click', async () => {
    const user = userEvent.setup();
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.enrich}
        value={{ indicator_field: 'alert.src_ip' }}
        onChange={vi.fn()}
      />,
    );

    const toggle = screen.getByRole('button', { name: /Advanced \(raw JSON\)/i });
    expect(screen.queryByText(/"indicator_field"/)).not.toBeInTheDocument();

    await user.click(toggle);

    // Now the textarea is visible with the JSON.
    const textarea = screen.getByDisplayValue(/"indicator_field"/);
    expect(textarea).toBeInTheDocument();
  });

  it('flags malformed JSON in the raw escape hatch without firing onChange', async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <SchemaForm
        schema={STEP_SCHEMAS.enrich}
        value={{ indicator_field: 'alert.src_ip' }}
        onChange={onChange}
      />,
    );

    await user.click(
      screen.getByRole('button', { name: /Advanced \(raw JSON\)/i }),
    );
    const textarea = screen.getByDisplayValue(/"indicator_field"/);
    onChange.mockClear();
    // fireEvent.change avoids userEvent's curly-brace key-descriptor syntax,
    // which would mis-parse "{not json" as a key combo.
    fireEvent.change(textarea, { target: { value: '{not json' } });

    // No onChange because the parse failed.
    expect(onChange).not.toHaveBeenCalled();
    // And an inline error message surfaces. Browsers/Node phrase JSON parse
    // errors slightly differently across versions, so accept any of the
    // common shapes.
    expect(
      screen.getByText(/Unexpected token|Invalid JSON|in JSON|JSON\.parse/i),
    ).toBeInTheDocument();
  });
});

describe('defaultParamsFor', () => {
  it('seeds defaults for fields that declare them', () => {
    const params = defaultParamsFor('create_ticket');
    expect(params).toEqual({
      priority: 'P2',
      queue: 'soc',
    });
  });

  it('returns an empty object when the schema declares no defaults', () => {
    expect(defaultParamsFor('enrich')).toEqual({});
    // condition has no fields → also empty.
    expect(defaultParamsFor('condition')).toEqual({});
  });
});

describe('validateStepParams', () => {
  it('flags missing required fields', () => {
    const errors = validateStepParams('block_ip', {});
    expect(errors).toEqual(
      expect.arrayContaining([
        'IP address field is required.',
        'Duration (seconds) is required.',
      ]),
    );
  });

  it('returns no errors for a fully-populated valid step', () => {
    const errors = validateStepParams('block_ip', {
      ip_field: 'alert.src_ip',
      duration: 3600,
    });
    expect(errors).toEqual([]);
  });

  it('coerces a non-numeric duration into a type error', () => {
    const errors = validateStepParams('block_ip', {
      ip_field: 'alert.src_ip',
      duration: '3600',
    });
    expect(errors).toEqual(
      expect.arrayContaining(['Duration (seconds) must be a number.']),
    );
  });

  it('requires service_key_env when the notify channel is pagerduty', () => {
    const errors = validateStepParams('notify', {
      channel: 'pagerduty',
      message_template: 'hi',
    });
    expect(errors).toEqual(
      expect.arrayContaining([
        'PagerDuty channel requires a service-key env var.',
      ]),
    );
  });

  it('requires webhook_env when the notify channel is webhook', () => {
    const errors = validateStepParams('notify', {
      channel: 'webhook',
      message_template: 'hi',
    });
    expect(errors).toEqual(
      expect.arrayContaining([
        'Webhook channel requires a webhook env var.',
      ]),
    );
  });

  it('does not require pagerduty/webhook envs for slack notify', () => {
    const errors = validateStepParams('notify', {
      channel: 'slack',
      message_template: 'hi',
    });
    expect(errors).toEqual([]);
  });
});
