/**
 * OrcaRouter Cyber Inference — settings panel.
 *
 * What this holds the UI to:
 *
 *   • the model field is a real `<select>` fed by the server catalog, never a
 *     free-text input, and recommended cyber models are offered above it;
 *   • switching provider clears the model, so an OpenAI id cannot be carried
 *     into an OrcaRouter credential;
 *   • a degraded discovery is labelled as the verified fallback, not as a live
 *     answer;
 *   • both authentication methods exist in one panel: paste a key, or
 *     "Connect with OrcaRouter" (OAuth 2.0 + PKCE, out-of-band), and the code
 *     is dropped from state on `pagehide`;
 *   • a 401/403 on the stored key is rendered as "re-authentication needed",
 *     which is what a durable key without a refresh grant means.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
const swrLoadingKeys = vi.hoisted(() => new Set<string>());
const swrMutate = vi.hoisted(() => vi.fn());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: swrLoadingKeys.has(k),
      mutate: swrMutate,
    };
  },
}));

const mockGetLlmCredential = vi.hoisted(() => vi.fn());
const mockUpsertLlmCredential = vi.hoisted(() => vi.fn());
const mockDeleteLlmCredential = vi.hoisted(() => vi.fn());
const mockGetAirgapStatus = vi.hoisted(() => vi.fn());
const mockGetLlmStatus = vi.hoisted(() => vi.fn());
const mockGetConnectors = vi.hoisted(() => vi.fn());
const mockGetConnectorStatuses = vi.hoisted(() => vi.fn());
const mockListModels = vi.hoisted(() => vi.fn());
const mockStartConnect = vi.hoisted(() => vi.fn());
const mockFinishConnect = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  deploymentApi: {
    getAirgapStatus: mockGetAirgapStatus,
    getLlmStatus: mockGetLlmStatus,
    getLlmCredential: mockGetLlmCredential,
    upsertLlmCredential: mockUpsertLlmCredential,
    deleteLlmCredential: mockDeleteLlmCredential,
    listOrcaRouterModels: mockListModels,
    startOrcaRouterConnect: mockStartConnect,
    finishOrcaRouterConnect: mockFinishConnect,
  },
  connectorsApi: {
    list: mockGetConnectors,
    statuses: mockGetConnectorStatuses,
  },
  ApiError: class ApiError extends Error {
    status: number;
    body?: string;
    constructor(message: string, status = 500, body?: string) {
      super(message);
      this.status = status;
      this.body = body;
    }
  },
}));

const mockToastSuccess = vi.hoisted(() => vi.fn());
const mockToastError = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: mockToastSuccess,
    error: mockToastError,
  },
  toast: {
    success: mockToastSuccess,
    error: mockToastError,
  },
}));

import { SettingsView } from './SettingsView';
import type {
  LlmCredentialView,
  OrcaRouterCatalog,
  OrcaRouterConnectStart,
} from '@/lib/api';

// ──────────────────────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────────────────────

const AIRGAP_KEY = 'settings:airgap-status';
const LLM_KEY = 'settings:llm-status';
const CRED_KEY = 'settings:llm-credential';

const recommendation = (
  id: string,
  name: string,
): OrcaRouterCatalog['recommended'][number] => ({
  id,
  name,
  context_length: null,
  input_modalities: ['text'],
  supported_endpoint_types: ['openai'],
  reasoning_efforts: [],
});

const CATALOG: OrcaRouterCatalog = {
  object: 'list',
  source: 'live',
  degraded: false,
  detail: '',
  default_model: 'orcarouter/auto',
  recommended: [
    recommendation('orcarouter/auto', 'OrcaRouter Auto (default routing)'),
    recommendation('orcacyber-ultra-1.0', 'OrcaCyber Ultra'),
    recommendation('orcacyber-zero-1.5', 'OrcaCyber Zero'),
    recommendation('orcarouter/fusion', 'OrcaRouter Fusion (general fallback)'),
  ],
  data: [
    {
      id: 'openai/gpt-5.5',
      name: 'OpenAI GPT-5.5',
      context_length: 400000,
      input_modalities: ['text', 'image'],
      supported_endpoint_types: ['openai'],
      reasoning_efforts: ['low', 'medium', 'high'],
    },
    {
      id: 'deepseek/deepseek-v4-pro',
      name: 'DeepSeek V4 Pro',
      context_length: 1000000,
      input_modalities: ['text'],
      supported_endpoint_types: ['openai'],
      reasoning_efforts: [],
    },
  ],
};

const DEGRADED: OrcaRouterCatalog = {
  ...CATALOG,
  source: 'fallback',
  degraded: true,
  detail: 'The catalog request timed out after 10s.',
  data: [
    {
      id: 'openai/gpt-5.5',
      name: 'OpenAI GPT-5.5',
      context_length: null,
      input_modalities: ['text'],
      supported_endpoint_types: ['openai'],
      reasoning_efforts: [],
    },
  ],
};

const CONNECT_START: OrcaRouterConnectStart = {
  authorize_url: 'https://www.orcarouter.ai/auth?state=state-value-1234567890',
  state: 'state-value-1234567890',
  expires_at: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  expires_in_seconds: 600,
  provider: 'orcarouter-oauth',
  flow: 'pkce-oob',
};

function credentialFixture(
  overrides: Partial<LlmCredentialView> = {},
): LlmCredentialView {
  return {
    provider: 'orcarouter',
    base_url: 'https://api.orcarouter.ai/v1',
    model: 'orcarouter/auto',
    has_api_key: true,
    enabled: true,
    settings: {},
    created_at: '2026-01-01T00:00:00Z',
    last_rotated_at: '2026-02-01T12:00:00Z',
    updated_at: '2026-02-01T12:00:00Z',
    ...overrides,
  };
}

const airgapFixture = {
  enabled: false,
  allowlist: [],
  implicit_private_suffixes: ['.local', '.internal'],
  policy: 'Air-gap disabled; all egress permitted.',
};

const llmFixture = {
  provider: 'openai',
  model: 'gpt-4o-mini',
  base_url: '',
  host: '',
  key_set: true,
  airgap_enabled: false,
  airgap_compliant: true,
  is_local: false,
  effective_path: 'live',
  policy_note: 'Live LLM calls enabled.',
  recent_health: 'unknown',
  recent_calls: 0,
  recent_failures: 0,
  recent_note: 'No calls observed yet.',
};

// ──────────────────────────────────────────────────────────────────────────────
// Render helpers
// ──────────────────────────────────────────────────────────────────────────────

async function renderDeploymentTab({
  credential = null,
}: {
  credential?: LlmCredentialView | null;
} = {}) {
  swrData.set(AIRGAP_KEY, airgapFixture);
  swrData.set(LLM_KEY, llmFixture);
  swrData.set(CRED_KEY, credential ?? undefined);

  render(<SettingsView />);
  const tab = await screen.findByRole('button', { name: /deployment.*ai/i });
  await userEvent.click(tab);
}

async function openFormWithOrcaRouterAPIKey() {
  const configure = await screen.findByRole('button', { name: /configure byok/i });
  await userEvent.click(configure);
  const provider = await screen.findByRole('combobox', { name: /provider/i });
  await userEvent.selectOptions(provider, 'orcarouter');
}

// ──────────────────────────────────────────────────────────────────────────────
describe('OrcaRouter — model selection is a real catalog', () => {
  beforeEach(() => {
    swrData.clear();
    swrErrors.clear();
    swrLoadingKeys.clear();
    vi.clearAllMocks();
    mockListModels.mockResolvedValue(CATALOG);
    mockUpsertLlmCredential.mockResolvedValue(credentialFixture());
  });

  it('loads the dropdown from the server once a key is entered, with cyber models recommended', async () => {
    await renderDeploymentTab();
    await openFormWithOrcaRouterAPIKey();

    // No key yet: no request, and the user is told why.
    expect(mockListModels).not.toHaveBeenCalled();
    expect(
      await screen.findByText(/paste a key to load the model list/i),
    ).toBeInTheDocument();

    await userEvent.type(
      screen.getByLabelText(/api key/i),
      'sk-orca-test-not-a-real-key',
    );

    await waitFor(
      () => expect(mockListModels).toHaveBeenCalledTimes(1),
      { timeout: 3000 },
    );
    expect(mockListModels).toHaveBeenCalledWith({
      api_key: 'sk-orca-test-not-a-real-key',
    });

    const modelSelect = await screen.findByRole('combobox', { name: /^model$/i });
    expect(
      await screen.findByRole('option', { name: /OrcaCyber Ultra/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('option', { name: /OrcaCyber Zero/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('option', { name: /OrcaRouter Auto/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('option', { name: /OpenAI GPT-5.5/i }),
    ).toBeInTheDocument();
    expect(modelSelect).toHaveValue('orcarouter/auto');
    // The free-text model input is gone for this provider.
    expect(screen.queryByPlaceholderText('provider default')).not.toBeInTheDocument();
  });

  it('sends the chosen model and a null base URL to the credential API', async () => {
    await renderDeploymentTab();
    await openFormWithOrcaRouterAPIKey();

    await userEvent.type(screen.getByLabelText(/api key/i), 'sk-orca-test-key');
    const select = await screen.findByRole('combobox', { name: /^model$/i });
    await screen.findByRole('option', { name: /OrcaCyber Ultra/i });
    await userEvent.selectOptions(select, 'orcacyber-ultra-1.0');

    await userEvent.click(screen.getByRole('button', { name: /save credential/i }));

    await waitFor(() =>
      expect(mockUpsertLlmCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'orcarouter',
          base_url: null,
          model: 'orcacyber-ultra-1.0',
          api_key: 'sk-orca-test-key',
          enabled: true,
        }),
      ),
    );
  });

  it('labels a failed discovery as the verified fallback, not a live answer', async () => {
    mockListModels.mockResolvedValue(DEGRADED);
    await renderDeploymentTab();
    await openFormWithOrcaRouterAPIKey();
    await userEvent.type(screen.getByLabelText(/api key/i), 'sk-orca-test-key');

    expect(
      await screen.findByText(/showing the verified fallback list/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('group', { name: /verified fallback models/i }),
    ).toBeInTheDocument();
    // The failure reason is carried, not swallowed.
    expect(
      screen.getByText(/catalog request timed out/i),
    ).toBeInTheDocument();
  });

  it('clears the model when the provider changes', async () => {
    await renderDeploymentTab();
    const configure = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configure);

    const modelInput = screen.getByPlaceholderText('provider default');
    await userEvent.type(modelInput, 'gpt-4o');
    expect(modelInput).toHaveValue('gpt-4o');

    const provider = screen.getByRole('combobox', { name: /provider/i });
    await userEvent.selectOptions(provider, 'orcarouter');

    const select = await screen.findByRole('combobox', { name: /^model$/i });
    expect(select).toHaveValue('');
    await userEvent.type(screen.getByLabelText(/api key/i), 'sk-orca-test-key');
    await waitFor(() =>
      expect(screen.getByRole('combobox', { name: /^model$/i })).toHaveValue(
        'orcarouter/auto',
      ),
    );
  });
});

// ──────────────────────────────────────────────────────────────────────────────
describe('OrcaRouter — sign-in (OAuth 2.0 + PKCE, out-of-band)', () => {
  beforeEach(() => {
    swrData.clear();
    swrErrors.clear();
    swrLoadingKeys.clear();
    vi.clearAllMocks();
    mockListModels.mockResolvedValue(CATALOG);
    mockStartConnect.mockResolvedValue(CONNECT_START);
    mockFinishConnect.mockResolvedValue(
      credentialFixture({ provider: 'orcarouter-oauth' }),
    );
    vi.spyOn(window, 'open').mockReturnValue({} as Window);
  });

  async function openConnectPanel() {
    await renderDeploymentTab();
    const configure = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configure);
    const provider = await screen.findByRole('combobox', { name: /provider/i });
    await userEvent.selectOptions(provider, 'orcarouter-oauth');
    await userEvent.click(
      await screen.findByRole('button', { name: /connect with orcarouter/i }),
    );
    return screen.findByLabelText(/authorization code/i);
  }

  it('starts a PKCE flow, shows the consent link, and redeems the pasted code', async () => {
    const codeInput = await openConnectPanel();

    expect(mockStartConnect).toHaveBeenCalledTimes(1);
    expect(window.open).toHaveBeenCalledWith(
      CONNECT_START.authorize_url,
      '_blank',
      'noopener,noreferrer',
    );
    expect(
      screen.getByRole('link', { name: /www\.orcarouter\.ai\/auth/i }),
    ).toHaveAttribute('href', CONNECT_START.authorize_url);

    await userEvent.type(codeInput, 'oob-code-123');
    await userEvent.click(screen.getByRole('button', { name: /^finish$/i }));

    await waitFor(() =>
      expect(mockFinishConnect).toHaveBeenCalledWith({
        state: CONNECT_START.state,
        code: 'oob-code-123',
      }),
    );
    await waitFor(() =>
      expect(mockToastSuccess).toHaveBeenCalledWith(
        expect.stringContaining('OrcaRouter connected'),
      ),
    );
    // Once connected, discovery runs with the stored key — never with a value
    // typed into this panel.
    await waitFor(() =>
      expect(mockListModels).toHaveBeenCalledWith({ api_key: undefined }),
    );
  });

  it('drops the pasted code when the page is hidden', async () => {
    const codeInput = await openConnectPanel();
    await userEvent.type(codeInput, 'oob-code-123');
    expect(codeInput).toHaveValue('oob-code-123');

    window.dispatchEvent(new Event('pagehide'));

    await waitFor(() =>
      expect(
        screen.queryByLabelText(/authorization code/i),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.getByRole('button', { name: /connect with orcarouter/i }),
    ).toBeInTheDocument();
  });

  it('refuses to save before an account is connected', async () => {
    await renderDeploymentTab();
    const configure = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configure);
    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: /provider/i }),
      'orcarouter-oauth',
    );

    await userEvent.click(screen.getByRole('button', { name: /save credential/i }));

    expect(
      await screen.findByText(/connect your orcarouter account before saving/i),
    ).toBeInTheDocument();
    expect(mockUpsertLlmCredential).not.toHaveBeenCalled();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
describe('OrcaRouter — stored credential states', () => {
  beforeEach(() => {
    swrData.clear();
    swrErrors.clear();
    swrLoadingKeys.clear();
    vi.clearAllMocks();
    mockListModels.mockResolvedValue(CATALOG);
    mockGetLlmCredential.mockResolvedValue(credentialFixture());
  });

  it('shows both authentication methods as distinct providers', async () => {
    await renderDeploymentTab({ credential: credentialFixture() });
    await userEvent.click(await screen.findByRole('button', { name: /^edit$/i }));
    const provider = screen.getByRole('combobox', { name: /provider/i });
    const labels = Array.from(provider.querySelectorAll('option')).map(o => o.textContent);
    expect(labels).toContain('OrcaRouter Cyber Inference — API key');
    expect(labels).toContain('OrcaRouter Cyber Inference — Sign in');
  });

  it('renders a rejected key as re-authentication, not as a transient error', async () => {
    await renderDeploymentTab({
      credential: credentialFixture({ needs_reauth: true }),
    });
    expect(
      await screen.findByText('Re-authentication needed'),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/no refresh grant/i),
    ).toBeInTheDocument();
  });
});
