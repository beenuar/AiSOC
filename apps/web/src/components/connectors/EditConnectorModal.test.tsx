/**
 * Editing a saved connector sends what the operator changed and nothing else.
 *
 * The Configure button used to be disabled ("planned for v1.1") and the
 * handler behind it answered "Delete + re-add". A re-added connector loses its
 * id, its checkpoint, its event counters and its push ingest token, and the
 * connector pages already told operators to rotate tokens "via the AiSOC
 * connector edit screen" that did not exist.
 *
 * The edit dialog cannot show a stored secret — the API never returns one —
 * so its contract is the PATCH body: a blank secret is not sent (the stored
 * one is kept), a typed secret replaces only its own key, an untouched setting
 * is not sent, and a cleared optional setting is sent as `null` so the API
 * removes it. Anything else in `connector_config` (the scheduler's
 * `checkpoint`, `filter_rules`) is never part of the body at all.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Connector, ConnectorCatalogEntry, ConnectorSchemaField } from '@/lib/api';

const api = vi.hoisted(() => ({
  catalog: vi.fn(),
  update: vi.fn(),
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    connectorsApi: { ...actual.connectorsApi, catalog: api.catalog, update: api.update },
  };
});

const toastMock = vi.hoisted(() => Object.assign(vi.fn(), { success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: toastMock }));

import {
  EditConnectorModal,
  buildConnectorPatch,
  buildEditValues,
  missingRequiredFields,
} from './EditConnectorModal';
import { ConnectorInstanceList } from './ConnectorInstanceList';

const FIELDS: ConnectorSchemaField[] = [
  { name: 'okta_domain', type: 'string', label: 'Okta domain', required: true },
  { name: 'api_token', type: 'secret', label: 'API token', required: true },
  { name: 'page_size', type: 'number', label: 'Page size', required: false, default: 200 },
  { name: 'proxy_url', type: 'string', label: 'Proxy URL', required: false },
];

const ENTRY: ConnectorCatalogEntry = {
  connector_id: 'okta',
  connector_name: 'Okta',
  category: 'iam',
  description: 'Okta System Log',
  fields: FIELDS,
};

const CONNECTOR: Connector = {
  id: 'c0ffee00-0000-0000-0000-000000000001',
  name: 'Okta production',
  type: 'okta',
  status: 'active',
  enabled: true,
  config: {
    okta_domain: 'acme.okta.com',
    page_size: 500,
    proxy_url: 'https://proxy.acme.example',
    checkpoint: { after: 'cursor-41' },
    filter_rules: [{ field: 'severity', op: 'eq', value: 'debug', action: 'drop' }],
  },
};

// ─── Pure helpers ────────────────────────────────────────────────────────────

describe('buildEditValues', () => {
  it('shows stored settings, and never a secret', () => {
    expect(buildEditValues(FIELDS, CONNECTOR.config)).toEqual({
      okta_domain: 'acme.okta.com',
      api_token: '',
      page_size: 500,
      proxy_url: 'https://proxy.acme.example',
    });
  });

  it('falls back to where the add wizard starts a field the instance has no value for', () => {
    expect(buildEditValues(FIELDS, { okta_domain: 'acme.okta.com' })).toMatchObject({
      page_size: 200,
      proxy_url: '',
    });
  });

  it('ignores stored keys that are not schema fields', () => {
    const values = buildEditValues(FIELDS, CONNECTOR.config);
    expect(values).not.toHaveProperty('checkpoint');
    expect(values).not.toHaveProperty('filter_rules');
  });
});

describe('buildConnectorPatch', () => {
  const initial = buildEditValues(FIELDS, CONNECTOR.config);

  it('is empty when nothing changed, so a save cannot rewrite anything', () => {
    expect(buildConnectorPatch(FIELDS, initial, initial)).toEqual({});
  });

  it('sends a typed secret on its own and a blank one not at all', () => {
    expect(buildConnectorPatch(FIELDS, initial, { ...initial, api_token: 'new-token' })).toEqual({
      auth_config: { api_token: 'new-token' },
    });
  });

  it('sends only the settings that changed', () => {
    expect(buildConnectorPatch(FIELDS, initial, { ...initial, page_size: 100 })).toEqual({
      connector_config: { page_size: 100 },
    });
  });

  it('sends a cleared optional setting as null, which the API reads as remove', () => {
    expect(buildConnectorPatch(FIELDS, initial, { ...initial, proxy_url: '' })).toEqual({
      connector_config: { proxy_url: null },
    });
  });
});

describe('missingRequiredFields', () => {
  it('names an emptied required setting but not a blank secret, which means keep', () => {
    const values = { ...buildEditValues(FIELDS, CONNECTOR.config), okta_domain: '' };
    expect(missingRequiredFields(FIELDS, values)).toEqual(['Okta domain']);
  });
});

// ─── The dialog ──────────────────────────────────────────────────────────────

beforeEach(() => {
  api.catalog.mockReset().mockResolvedValue({ connectors: [ENTRY] });
  api.update.mockReset().mockImplementation(async (id: string, body: { name?: string }) => ({
    ...CONNECTOR,
    id,
    name: body.name ?? CONNECTOR.name,
  }));
  toastMock.mockClear();
  toastMock.success.mockClear();
  toastMock.error.mockClear();
});

afterEach(() => {
  cleanup();
});

async function openDialog(onSaved = vi.fn(), onClose = vi.fn()) {
  render(<EditConnectorModal connector={CONNECTOR} onClose={onClose} onSaved={onSaved} />);
  await screen.findByDisplayValue('acme.okta.com');
  return { onSaved, onClose };
}

describe('EditConnectorModal', () => {
  it('prefills the stored settings and leaves the secret blank', async () => {
    await openDialog();

    expect(screen.getByLabelText(/Instance name/)).toHaveProperty('value', 'Okta production');
    expect(screen.getByLabelText(/Page size/)).toHaveProperty('value', '500');
    expect(screen.getByLabelText(/API token/)).toHaveProperty('value', '');
    expect(screen.getByRole('button', { name: 'Save changes' })).toHaveProperty('disabled', true);
  });

  it('rotates one secret and renames without sending any other setting', async () => {
    const user = userEvent.setup();
    const { onSaved, onClose } = await openDialog();

    const name = screen.getByLabelText(/Instance name/);
    await user.clear(name);
    await user.type(name, 'Okta staging');
    await user.type(screen.getByLabelText(/API token/), 'new-token');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(1));
    expect(api.update).toHaveBeenCalledWith(CONNECTOR.id, {
      name: 'Okta staging',
      auth_config: { api_token: 'new-token' },
    });
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(onSaved).toHaveBeenCalledWith(expect.objectContaining({ name: 'Okta staging' }));
  });

  it('removes a cleared optional setting and leaves the secret alone', async () => {
    const user = userEvent.setup();
    await openDialog();

    await user.clear(screen.getByLabelText(/Proxy URL/));
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(1));
    expect(api.update).toHaveBeenCalledWith(CONNECTOR.id, { connector_config: { proxy_url: null } });
  });

  it('refuses to save an emptied required setting', async () => {
    const user = userEvent.setup();
    const { onClose } = await openDialog();

    await user.clear(screen.getByLabelText(/Okta domain/));
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    expect(api.update).not.toHaveBeenCalled();
    expect(toastMock.error).toHaveBeenCalledWith('Required: Okta domain');
    expect(onClose).not.toHaveBeenCalled();
  });

  it('keeps the dialog open and says why when the save is refused', async () => {
    api.update.mockRejectedValueOnce(new Error('API 422 Unprocessable Entity'));
    const user = userEvent.setup();
    const { onSaved, onClose } = await openDialog();

    await user.type(screen.getByLabelText(/API token/), 'new-token');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(toastMock.error).toHaveBeenCalledWith('API 422 Unprocessable Entity'));
    expect(onSaved).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('still allows a rename when the catalog no longer has the connector type', async () => {
    api.catalog.mockResolvedValueOnce({ connectors: [] });
    const user = userEvent.setup();
    render(<EditConnectorModal connector={CONNECTOR} onClose={vi.fn()} />);

    expect(await screen.findByText(/no settings form for it/)).toBeTruthy();
    const name = screen.getByLabelText(/Instance name/);
    await user.clear(name);
    await user.type(name, 'Okta legacy');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => expect(api.update).toHaveBeenCalledWith(CONNECTOR.id, { name: 'Okta legacy' }));
  });

  it('renders nothing while no connector is being edited', () => {
    render(<EditConnectorModal connector={null} onClose={vi.fn()} />);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(api.catalog).not.toHaveBeenCalled();
  });
});

describe('ConnectorInstanceList', () => {
  it('offers Configure on each card and hands the parent that instance', async () => {
    const user = userEvent.setup();
    const onConfigure = vi.fn();
    render(
      <ConnectorInstanceList
        connectors={[CONNECTOR]}
        onTest={vi.fn()}
        onAdd={vi.fn()}
        onConfigure={onConfigure}
      />,
    );

    const configure = screen.getByRole('button', { name: `Configure ${CONNECTOR.name}` });
    expect(configure).toHaveProperty('disabled', false);
    await user.click(configure);
    expect(onConfigure).toHaveBeenCalledWith(CONNECTOR);
  });
});
