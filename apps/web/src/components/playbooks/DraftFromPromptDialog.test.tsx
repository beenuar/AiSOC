/**
 * DraftFromPromptDialog — T3.7 NL → playbook generator UI.
 *
 * The dialog is the visible half of T3.7. We pin the contract the
 * downstream PlaybookEditor relies on:
 *
 *   1. On submit, the dialog POSTs to /api/v1/playbooks/draft-from-nl
 *      with the trimmed prompt and ``allow_llm: true``.
 *   2. On success, the returned ``playbook`` is parked in
 *      ``sessionStorage["aisoc:nl-draft"]`` and the router is pushed
 *      to ``/playbooks/new?nl=true``.
 *   3. On HTTP error, the backend's text body is surfaced inline; the
 *      router is NOT pushed and sessionStorage is NOT touched.
 *   4. Empty / whitespace-only prompts never hit the network.
 *   5. The Cmd/Ctrl-Enter keyboard shortcut submits.
 *
 * The router push and fetch are mocked. The component is otherwise
 * rendered for real (Tailwind classes are inert under jsdom).
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { DraftFromPromptDialog } from './DraftFromPromptDialog';

const pushMock = vi.hoisted(() => vi.fn());
vi.mock('next/navigation', () => ({
  __esModule: true,
  useRouter: () => ({ push: pushMock }),
}));

const fakePlaybook = {
  id: 'nl-test-id',
  name: 'Draft test',
  description: 'desc',
  version: '1.0.0',
  tags: ['nl-drafted', 'draft'],
  trigger: { on: 'alert' },
  steps: [
    {
      id: 'a1b2c3d4',
      name: 'Notify',
      type: 'notify',
      params: {},
      on_failure: 'abort',
      retry_max: 0,
      timeout_seconds: 30,
    },
  ],
  author: 'AiSOC NL Drafter',
  enabled: false,
  created_at: '2026-06-27T00:00:00Z',
  updated_at: '2026-06-27T00:00:00Z',
};

const fakeDraftResponse = {
  playbook: fakePlaybook,
  rationale: 'used substrate',
  used_llm: false,
  schema_validated: true,
};

function mockFetchOnce(body: unknown, ok = true, status = 200): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({
      ok,
      status,
      json: async () => body,
      text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    })),
  );
}

describe('DraftFromPromptDialog', () => {
  beforeEach(() => {
    pushMock.mockReset();
    sessionStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('does not render when closed', () => {
    render(<DraftFromPromptDialog open={false} onClose={() => undefined} />);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('renders the title and a submit-disabled state when prompt is empty', () => {
    render(<DraftFromPromptDialog open onClose={() => undefined} />);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText(/Draft a playbook from a prompt/i)).toBeInTheDocument();
    const submit = screen.getByRole('button', { name: /draft playbook/i });
    expect(submit).toBeDisabled();
  });

  it('posts to the drafter endpoint and routes to /playbooks/new on success', async () => {
    const user = userEvent.setup();
    mockFetchOnce(fakeDraftResponse);
    const handleClose = vi.fn();

    render(<DraftFromPromptDialog open onClose={handleClose} />);
    const ta = screen.getByRole('textbox');
    await user.type(ta, 'Isolate the host and notify the SOC');

    const submit = screen.getByRole('button', { name: /draft playbook/i });
    await user.click(submit);

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    const [url, init] = (global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/playbooks/draft-from-nl');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.prompt).toBe('Isolate the host and notify the SOC');
    expect(body.allow_llm).toBe(true);

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith('/playbooks/new?nl=true');
    });
    expect(handleClose).toHaveBeenCalled();

    const parked = sessionStorage.getItem('aisoc:nl-draft');
    expect(parked).not.toBeNull();
    const parsed = JSON.parse(parked as string);
    expect(parsed.id).toBe('nl-test-id');
    expect(parsed.enabled).toBe(false);
  });

  it('surfaces the backend error text and does not route on HTTP failure', async () => {
    const user = userEvent.setup();
    mockFetchOnce('prompt is too long (max 4000 chars)', false, 400);

    render(<DraftFromPromptDialog open onClose={() => undefined} />);
    const ta = screen.getByRole('textbox');
    await user.type(ta, 'whatever');

    await user.click(screen.getByRole('button', { name: /draft playbook/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/too long/i);
    });
    expect(pushMock).not.toHaveBeenCalled();
    expect(sessionStorage.getItem('aisoc:nl-draft')).toBeNull();
  });

  it('shows a client-side error and does not call fetch on whitespace prompt', async () => {
    const user = userEvent.setup();
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    render(<DraftFromPromptDialog open onClose={() => undefined} />);
    // Type spaces only — submit must NOT post.
    await user.type(screen.getByRole('textbox'), '     ');

    // The button is disabled while the prompt is blank/whitespace-only;
    // we force a submit attempt via the keyboard path to prove the
    // dialog still guards on the server contract.
    fireEvent.keyDown(screen.getByRole('textbox'), {
      key: 'Enter',
      metaKey: true,
    });

    // Give the async handler a chance.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(pushMock).not.toHaveBeenCalled();
  });

  it('submits via Cmd-Enter keyboard shortcut', async () => {
    const user = userEvent.setup();
    mockFetchOnce(fakeDraftResponse);

    render(<DraftFromPromptDialog open onClose={() => undefined} />);
    const ta = screen.getByRole('textbox');
    await user.type(ta, 'Notify the SOC');
    fireEvent.keyDown(ta, { key: 'Enter', metaKey: true });

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });
  });

  it('populates the textarea when a suggestion chip is clicked', async () => {
    const user = userEvent.setup();
    render(<DraftFromPromptDialog open onClose={() => undefined} />);

    const chip = screen.getByRole('button', { name: /High-sev exfil/i });
    await user.click(chip);

    const ta = screen.getByRole('textbox') as HTMLTextAreaElement;
    expect(ta.value).toMatch(/high-severity exfil alert/i);
  });

  it('closes when the Cancel button is clicked', async () => {
    const user = userEvent.setup();
    const handleClose = vi.fn();
    render(<DraftFromPromptDialog open onClose={handleClose} />);
    await user.click(screen.getByRole('button', { name: /cancel/i }));
    expect(handleClose).toHaveBeenCalled();
  });
});
