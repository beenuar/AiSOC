import { describe, expect, it } from 'vitest';
import { presentCopilotReply } from './copilotReply';
import type { CopilotMessage } from './api';

const reply: CopilotMessage = { id: 'r', role: 'assistant', content: 'The model answer.', createdAt: '2026-11-11' };

describe('copilot provenance shared by the dock and full page', () => {
  it('retains a no-data-read notice even when a language model answered', () => {
    expect(presentCopilotReply(reply, { source: 'llm', notice: 'No environment data was read.' }).content)
      .toContain('No environment data was read.');
  });
  it('labels a template response', () => {
    expect(presentCopilotReply(reply, { source: 'template' }).content).toContain('built-in template');
  });
  it('does not lose failed reads, truncation or uncited claims', () => {
    const content = presentCopilotReply(reply, {
      source: 'llm', grounding: { uncited: ['198.51.100.5'] },
      data_access: [{ status: 'could_not_check' }, { status: 'ok', truncated: true }],
    }).content;
    expect(content).toContain('could not be checked');
    expect(content).toContain('Evidence was truncated');
    expect(content).toContain('198.51.100.5');
    expect(content).toContain(reply.content);
  });
  it('also accepts persisted per-message provenance', () => {
    expect(presentCopilotReply({ ...reply, notice: 'No environment data was read.' }).content)
      .toContain('No environment data was read.');
  });
  it('leaves ordinary or user messages unchanged', () => {
    expect(presentCopilotReply(reply)).toBe(reply);
    const user = { ...reply, role: 'user' as const, notice: 'not an assistant warning' };
    expect(presentCopilotReply(user)).toBe(user);
  });
});
