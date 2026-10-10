/**
 * The LLM pill must not read "Live" while every call is failing (issue #1241).
 *
 * `LlmCard` derived its badge from `effective_path` alone — a *configuration*
 * value decided by whether a key is set and whether the air-gap policy would
 * permit the host. A deployment whose every completion times out therefore
 * rendered the emerald "Live" pill, which is the panel asserting something it
 * had never checked.
 *
 * `recent_health` carries the outcome of the calls the product actually made.
 * Three states, and `unknown` matters as much as `degraded`: a pod that has
 * observed nothing must not be rendered as healthy, and must not be rendered
 * as broken either.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
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

const noop = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({
  __esModule: true,
  deploymentApi: {
    getAirgapStatus: noop,
    getLlmStatus: noop,
    getLlmCredential: noop,
    upsertLlmCredential: noop,
    deleteLlmCredential: noop,
  },
  connectorsApi: { list: noop, statuses: noop },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status = 500) {
      super(message);
      this.status = status;
    }
  },
}));

vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: vi.fn(), error: vi.fn() },
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { SettingsView } from './SettingsView';
import type { LlmStatus } from '@/lib/api';

const AIRGAP_KEY = 'settings:airgap-status';
const LLM_KEY = 'settings:llm-status';
const CRED_KEY = 'settings:llm-credential';

const airgapFixture = {
  enabled: false,
  allowlist: [],
  implicit_private_suffixes: ['.local', '.internal'],
  policy: 'Air-gap disabled; all egress permitted.',
};

function llmFixture(overrides: Partial<LlmStatus> = {}): LlmStatus {
  return {
    provider: 'local-litellm',
    model: 'aisoc-triage',
    base_url: 'http://litellm:4000/v1',
    host: 'litellm',
    key_set: true,
    airgap_enabled: false,
    airgap_compliant: true,
    is_local: true,
    effective_path: 'live',
    policy_note: 'LLM calls are routed to a local provider (local-litellm).',
    recent_health: 'healthy',
    recent_calls: 6,
    recent_failures: 0,
    recent_note: 'The most recent LLM call succeeded (0 of the last 6 failed).',
    ...overrides,
  };
}

async function renderWith(llm: LlmStatus) {
  swrData.set(AIRGAP_KEY, airgapFixture);
  swrData.set(LLM_KEY, llm);
  swrData.set(CRED_KEY, undefined);
  render(<SettingsView />);
  await userEvent.click(
    await screen.findByRole('button', { name: /deployment.*ai/i }),
  );
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  swrLoadingKeys.clear();
});

describe('LLM provider pill reflects whether the provider answers', () => {
  it('reads Degraded, not Live, when recent calls are failing', async () => {
    await renderWith(
      llmFixture({
        recent_health: 'degraded',
        recent_calls: 5,
        recent_failures: 5,
        recent_note:
          'The most recent LLM call failed (ReadTimeout); 5 of the last 5 failed. ' +
          'If the provider is a local model on CPU, raise AISOC_LITELLM_REQUEST_TIMEOUT.',
      }),
    );

    expect(await screen.findByText('Degraded')).toBeInTheDocument();
    expect(screen.queryByText('Live')).not.toBeInTheDocument();
  });

  it('tells the operator why, rather than only that something is wrong', async () => {
    await renderWith(
      llmFixture({
        recent_health: 'degraded',
        recent_calls: 5,
        recent_failures: 5,
        recent_note:
          'The most recent LLM call failed (ReadTimeout); 5 of the last 5 failed. ' +
          'If the provider is a local model on CPU, raise AISOC_LITELLM_REQUEST_TIMEOUT.',
      }),
    );

    expect(await screen.findByText(/5 of the last 5 failed/)).toBeInTheDocument();
    expect(screen.getByText(/AISOC_LITELLM_REQUEST_TIMEOUT/)).toBeInTheDocument();
  });

  it('still reads Live when the provider is answering', async () => {
    await renderWith(llmFixture());
    expect(await screen.findByText('Live')).toBeInTheDocument();
    expect(screen.queryByText('Degraded')).not.toBeInTheDocument();
  });

  it('says calls are unobserved rather than claiming health it has not seen', async () => {
    await renderWith(
      llmFixture({
        recent_health: 'unknown',
        recent_calls: 0,
        recent_failures: 0,
        recent_note:
          'No LLM call has been observed by this pod recently, so whether the provider ' +
          'answers is unmeasured. This reports configuration only.',
      }),
    );

    // Configuration is live, so the path badge stays — but the panel must not
    // present an unobserved provider as a verified-working one.
    expect(await screen.findByText('Live')).toBeInTheDocument();
    expect(screen.getByText(/No LLM call has been observed/)).toBeInTheDocument();
  });

  it('keeps the fallback badge winning over the health signal', async () => {
    // A deployment with no key is on the deterministic path: no call is even
    // attempted, so "degraded" would be the wrong story to lead with.
    await renderWith(
      llmFixture({
        key_set: false,
        effective_path: 'fallback',
        recent_health: 'unknown',
        recent_calls: 0,
        recent_failures: 0,
        recent_note: 'No LLM call has been observed by this pod recently.',
      }),
    );

    expect(await screen.findByText('Fallback path')).toBeInTheDocument();
    expect(screen.queryByText('Live')).not.toBeInTheDocument();
    expect(screen.queryByText('Degraded')).not.toBeInTheDocument();
  });
});
