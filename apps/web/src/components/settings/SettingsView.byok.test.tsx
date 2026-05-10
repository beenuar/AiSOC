/**
 * WS-H2 — BYOK per-tenant settings UI (vault-encrypted)
 *
 * Tests the BYOKCard component behaviour rendered inside DeploymentAIPanel
 * (which is part of SettingsView's "deployment" tab).
 *
 * Strategy
 * ─────────
 * • SWR is mocked so we control the data each hook key receives.
 * • deploymentApi is mocked to observe calls and inject errors.
 * • We render SettingsView, navigate to the "Deployment & AI" tab, then assert
 *   BYOKCard states (empty / view / edit / delete / error).
 *
 * Author: Beenu <beenu@cyble.com>
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// ──────────────────────────────────────────────────────────────────────────────
// SWR mock — keyed cache so we can return per-call data
// ──────────────────────────────────────────────────────────────────────────────
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

// ──────────────────────────────────────────────────────────────────────────────
// API mocks
// ──────────────────────────────────────────────────────────────────────────────
const mockGetLlmCredential = vi.hoisted(() => vi.fn());
const mockUpsertLlmCredential = vi.hoisted(() => vi.fn());
const mockDeleteLlmCredential = vi.hoisted(() => vi.fn());
const mockGetAirgapStatus = vi.hoisted(() => vi.fn());
const mockGetLlmStatus = vi.hoisted(() => vi.fn());
const mockGetConnectors = vi.hoisted(() => vi.fn());
const mockGetConnectorStatuses = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  deploymentApi: {
    getAirgapStatus: mockGetAirgapStatus,
    getLlmStatus: mockGetLlmStatus,
    getLlmCredential: mockGetLlmCredential,
    upsertLlmCredential: mockUpsertLlmCredential,
    deleteLlmCredential: mockDeleteLlmCredential,
  },
  connectorsApi: {
    list: mockGetConnectors,
    statuses: mockGetConnectorStatuses,
  },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status = 500) {
      super(message);
      this.status = status;
    }
  },
}));

// toast mock — capture messages
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

// date-fns formatDistanceToNow — stable output
vi.mock('date-fns', async () => {
  const actual = await vi.importActual<typeof import('date-fns')>('date-fns');
  return {
    ...actual,
    formatDistanceToNow: () => '3 months ago',
  };
});

// ──────────────────────────────────────────────────────────────────────────────
// Import under test (after mocks)
// ──────────────────────────────────────────────────────────────────────────────
import { SettingsView } from './SettingsView';
import type { LlmCredentialView } from '@/lib/api';

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────
const AIRGAP_KEY = 'settings:airgap-status';
const LLM_KEY = 'settings:llm-status';
const CRED_KEY = 'settings:llm-credential';

function credentialFixture(
  overrides: Partial<LlmCredentialView> = {},
): LlmCredentialView {
  return {
    provider: 'openai',
    base_url: null,
    model: 'gpt-4o-mini',
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
};

/** Render SettingsView with the "Deployment & AI" tab pre-selected. */
async function renderDeploymentTab(options: {
  credential?: LlmCredentialView | null;
  credentialError?: unknown;
  credentialLoading?: boolean;
} = {}) {
  const { credential = null, credentialError, credentialLoading = false } = options;

  swrData.set(AIRGAP_KEY, airgapFixture);
  swrData.set(LLM_KEY, llmFixture);

  if (credentialLoading) {
    swrLoadingKeys.add(CRED_KEY);
    swrData.delete(CRED_KEY);
  } else if (credentialError != null) {
    swrErrors.set(CRED_KEY, credentialError);
    swrData.delete(CRED_KEY);
  } else if (credential !== null) {
    swrData.set(CRED_KEY, credential);
    swrErrors.delete(CRED_KEY);
  } else {
    // null credential → no override configured
    swrData.set(CRED_KEY, undefined);
    swrErrors.delete(CRED_KEY);
  }

  render(<SettingsView />);

  // Navigate to the Deployment & AI tab
  const deploymentTab = await screen.findByRole('button', {
    name: /deployment.*ai/i,
  });
  await userEvent.click(deploymentTab);
}

function clearSwrMaps() {
  swrData.clear();
  swrErrors.clear();
  swrLoadingKeys.clear();
}

// ──────────────────────────────────────────────────────────────────────────────
describe('WS-H2 — BYOKCard: empty state (no credential)', () => {
  beforeEach(() => {
    clearSwrMaps();
    vi.clearAllMocks();
  });

  it('shows the BYOK section heading and "Configure BYOK" button when no credential exists', async () => {
    await renderDeploymentTab({ credential: null });

    expect(
      await screen.findByText('Bring-your-own-LLM (BYOK)'),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /configure byok/i }),
    ).toBeInTheDocument();
  });

  it('opens the edit form when "Configure BYOK" is clicked', async () => {
    await renderDeploymentTab({ credential: null });

    const btn = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(btn);

    expect(
      await screen.findByText(/configure byok credential/i),
    ).toBeInTheDocument();

    expect(screen.getByRole('combobox', { name: /provider/i })).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
describe('WS-H2 — BYOKCard: view state (credential exists)', () => {
  beforeEach(() => {
    clearSwrMaps();
    vi.clearAllMocks();
  });

  it('renders credential details in read-only mode', async () => {
    const cred = credentialFixture({ provider: 'openai', model: 'gpt-4o-mini' });
    await renderDeploymentTab({ credential: cred });

    // The BYOK heading confirms the card is rendered
    const byokSection = await screen.findByText('Bring-your-own-LLM (BYOK)');
    expect(byokSection).toBeInTheDocument();

    // "OpenAI" may appear in both LlmCard and BYOKCard — assert at least one occurrence
    expect(screen.getAllByText('OpenAI').length).toBeGreaterThanOrEqual(1);

    // Model shown — may appear in LlmCard and BYOKCard
    expect(screen.getAllByText('gpt-4o-mini').length).toBeGreaterThanOrEqual(1);

    // API key indicator
    expect(screen.getByText('Set (vault-encrypted)')).toBeInTheDocument();
  });

  it('shows "Active" status pill when credential.enabled is true', async () => {
    await renderDeploymentTab({ credential: credentialFixture({ enabled: true }) });
    // The BYOK heading confirms BYOKCard is present; "Active" is its status pill
    expect(await screen.findByText('Bring-your-own-LLM (BYOK)')).toBeInTheDocument();
    expect(screen.getAllByText('Active').length).toBeGreaterThanOrEqual(1);
  });

  it('shows "Disabled" status pill when credential.enabled is false', async () => {
    await renderDeploymentTab({ credential: credentialFixture({ enabled: false }) });
    // AirgapCard (disabled) and BYOKCard (disabled) may both render "Disabled"
    expect(await screen.findByText('Bring-your-own-LLM (BYOK)')).toBeInTheDocument();
    expect(screen.getAllByText('Disabled').length).toBeGreaterThanOrEqual(1);
  });

  it('shows "Edit" and "Remove" buttons', async () => {
    await renderDeploymentTab({ credential: credentialFixture() });
    expect(await screen.findByRole('button', { name: /^edit$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^remove$/i })).toBeInTheDocument();
  });

  it('switches to edit form when "Edit" is clicked', async () => {
    await renderDeploymentTab({ credential: credentialFixture() });

    const editBtn = await screen.findByRole('button', { name: /^edit$/i });
    await userEvent.click(editBtn);

    expect(
      await screen.findByText(/edit byok credential/i),
    ).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
describe('WS-H2 — BYOKCard: edit/create form', () => {
  beforeEach(() => {
    clearSwrMaps();
    vi.clearAllMocks();
    mockUpsertLlmCredential.mockResolvedValue(undefined);
  });

  it('calls upsertLlmCredential with correct payload on save', async () => {
    await renderDeploymentTab({ credential: null });

    // Open form
    const configureBtn = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configureBtn);

    // Provider defaults to 'openai', which requires an API key
    const apiKeyInput = await screen.findByLabelText(/api key/i);
    await userEvent.type(apiKeyInput, 'sk-test-key-123');

    const modelInput = screen.getByPlaceholderText('provider default');
    await userEvent.type(modelInput, 'gpt-4o');

    const saveBtn = screen.getByRole('button', { name: /save credential/i });
    await userEvent.click(saveBtn);

    await waitFor(() =>
      expect(mockUpsertLlmCredential).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'openai',
          api_key: 'sk-test-key-123',
          model: 'gpt-4o',
          enabled: true,
        }),
      ),
    );
    expect(mockToastSuccess).toHaveBeenCalledWith('BYOK credential saved.');
  });

  it('shows inline validation error when openai API key is missing', async () => {
    await renderDeploymentTab({ credential: null });

    const configureBtn = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configureBtn);

    // Do NOT fill in API key — provider is openai which requires one
    const saveBtn = await screen.findByRole('button', { name: /save credential/i });
    await userEvent.click(saveBtn);

    expect(await screen.findByText(/openai requires an api key/i)).toBeInTheDocument();
    expect(mockUpsertLlmCredential).not.toHaveBeenCalled();
  });

  it('requires base URL when provider is local-ollama', async () => {
    await renderDeploymentTab({ credential: null });

    const configureBtn = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configureBtn);

    const providerSelect = await screen.findByRole('combobox', { name: /provider/i });
    await userEvent.selectOptions(providerSelect, 'local-ollama');

    const saveBtn = screen.getByRole('button', { name: /save credential/i });
    await userEvent.click(saveBtn);

    expect(
      await screen.findByText(/local ollama requires a base url/i),
    ).toBeInTheDocument();
    expect(mockUpsertLlmCredential).not.toHaveBeenCalled();
  });

  it('shows API error message when upsert fails', async () => {
    mockUpsertLlmCredential.mockRejectedValue(new Error('Network failure'));
    await renderDeploymentTab({ credential: null });

    const configureBtn = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configureBtn);

    const apiKeyInput = await screen.findByLabelText(/api key/i);
    await userEvent.type(apiKeyInput, 'sk-any-key');

    const saveBtn = screen.getByRole('button', { name: /save credential/i });
    await userEvent.click(saveBtn);

    await waitFor(() =>
      expect(screen.getByText(/network failure/i)).toBeInTheDocument(),
    );
    expect(mockToastError).toHaveBeenCalled();
  });

  it('closes form on Cancel', async () => {
    await renderDeploymentTab({ credential: null });

    const configureBtn = await screen.findByRole('button', { name: /configure byok/i });
    await userEvent.click(configureBtn);

    expect(await screen.findByText(/configure byok credential/i)).toBeInTheDocument();

    const cancelBtn = screen.getByRole('button', { name: /cancel/i });
    await userEvent.click(cancelBtn);

    // Back to empty state
    expect(await screen.findByRole('button', { name: /configure byok/i })).toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
describe('WS-H2 — BYOKCard: delete flow', () => {
  beforeEach(() => {
    clearSwrMaps();
    vi.clearAllMocks();
    mockDeleteLlmCredential.mockResolvedValue(undefined);
  });

  it('requires double-click confirmation before deleting', async () => {
    const cred = credentialFixture();
    await renderDeploymentTab({ credential: cred });

    const removeBtn = await screen.findByRole('button', { name: /^remove$/i });
    await userEvent.click(removeBtn);

    // First click → becomes "Confirm remove"
    expect(
      screen.getByRole('button', { name: /confirm remove/i }),
    ).toBeInTheDocument();
    expect(mockDeleteLlmCredential).not.toHaveBeenCalled();
  });

  it('calls deleteLlmCredential on second click and shows toast', async () => {
    const cred = credentialFixture();
    await renderDeploymentTab({ credential: cred });

    // First click
    const removeBtn = await screen.findByRole('button', { name: /^remove$/i });
    await userEvent.click(removeBtn);

    // Second click (now labelled "Confirm remove")
    const confirmBtn = screen.getByRole('button', { name: /confirm remove/i });
    await userEvent.click(confirmBtn);

    await waitFor(() =>
      expect(mockDeleteLlmCredential).toHaveBeenCalledTimes(1),
    );
    expect(mockToastSuccess).toHaveBeenCalledWith(
      expect.stringContaining('BYOK credential removed'),
    );
  });

  it('cancels delete when Cancel link is clicked', async () => {
    const cred = credentialFixture();
    await renderDeploymentTab({ credential: cred });

    const removeBtn = await screen.findByRole('button', { name: /^remove$/i });
    await userEvent.click(removeBtn);

    const cancelLink = screen.getByRole('button', { name: /cancel/i });
    await userEvent.click(cancelLink);

    // Back to "Remove" (not "Confirm remove")
    expect(screen.getByRole('button', { name: /^remove$/i })).toBeInTheDocument();
    expect(mockDeleteLlmCredential).not.toHaveBeenCalled();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
describe('WS-H2 — BYOKCard: loading & error states', () => {
  beforeEach(() => {
    clearSwrMaps();
    vi.clearAllMocks();
  });

  it('renders a skeleton while credential is loading', async () => {
    await renderDeploymentTab({ credentialLoading: true });

    // The section heading should appear eventually (from the parent panel)
    // and a loading skeleton should be present (no "Configure BYOK" button yet)
    const deploymentSection = await screen.findByText('Deployment & AI');
    expect(deploymentSection).toBeInTheDocument();

    // No "Configure BYOK" or credential detail visible
    expect(
      screen.queryByRole('button', { name: /configure byok/i }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('Bring-your-own-LLM (BYOK)')).not.toBeInTheDocument();
  });

  it('shows BYOK panel unavailable message on error', async () => {
    const apiError = new Error('Forbidden');
    await renderDeploymentTab({ credentialError: apiError });

    expect(
      await screen.findByText(/byok panel unavailable/i),
    ).toBeInTheDocument();
  });
});
