import type { CopilotMessage } from './api';

/** Provenance travels with persisted messages as well as the first response. */
export interface CopilotProvenance {
  source?: 'llm' | 'template' | null;
  notice?: string | null;
  grounding?: { uncited?: string[] } | null;
  data_access?: Array<{ status: string; truncated?: boolean }>;
}

/** The dock and full page must not silently discard the same server warning. */
export function presentCopilotReply(
  reply: CopilotMessage & CopilotProvenance,
  metadata: CopilotProvenance = reply,
): CopilotMessage {
  if (reply.role !== 'assistant') return reply;
  const notices: string[] = [];
  if (metadata.notice) notices.push(metadata.notice);
  if (metadata.source === 'template' && !metadata.notice) {
    notices.push('This reply came from a built-in template, not a language model, and is not analysis of your environment.');
  }
  if (metadata.data_access?.some((read) => read.status !== 'ok')) {
    notices.push('Some data could not be checked. A failed read is not evidence of no activity.');
  }
  if (metadata.data_access?.some((read) => read.truncated)) {
    notices.push('Evidence was truncated. This answer does not cover all matching records.');
  }
  const uncited = metadata.grounding?.uncited ?? [];
  if (uncited.length > 0) {
    notices.push(`Not supported by anything this answer was given: ${uncited.join(', ')}. Verify before acting.`);
  }
  return notices.length > 0
    ? { ...reply, content: [...new Set(notices), '', '---', '', reply.content].join('\n') }
    : reply;
}

export function presentCopilotResponse(
  response: { reply: CopilotMessage } & CopilotProvenance,
): CopilotMessage {
  return presentCopilotReply(response.reply, response);
}
