'use client';

/**
 * ContextualActions — Phase 4A ambient Copilot UI.
 *
 * Drop this component anywhere in the app where the user is already looking
 * at a single entity (an alert, a case, a detection rule, a playbook) and
 * you'd like to surface contextual AI actions for it.
 *
 *   <ContextualActions
 *     page="alerts"
 *     entityId={alert.id}
 *     entity={alert}             // optional snapshot the LLM can read
 *     caseId={alert.caseId}      // optional, for ledger correlation
 *   />
 *
 * The component:
 *   • fetches the action catalogue from `/api/v1/contextual/actions`
 *     (cached in SWR) so the buttons match the backend's capabilities
 *   • renders one pill per supported action for the given page
 *   • opens an inline streaming panel under the pills when an action fires,
 *     consuming NDJSON from `/api/v1/contextual/action/stream`
 *   • shows follow-up suggestion chips when the stream completes
 *   • lets the user cancel mid-stream, copy the response, or close the panel
 *
 * Failure modes:
 *   • If the agents service is unreachable the buttons still render; the
 *     panel surfaces an inline error and the user can dismiss + retry.
 *   • If the backend is running without an LLM (no `OPENAI_API_KEY`), the
 *     stream emits a deterministic placeholder. The "fallback" badge in the
 *     panel header makes that obvious so the demo never lies.
 */

import type { ReactNode } from 'react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import {
  contextualApi,
  type ContextualActionDescriptor,
  type ContextualActionsCatalogue,
  type ContextualPage,
  type ContextualStreamFrame,
  type ContextualSuggestion,
} from '@/lib/api';

// ─── Public props ───────────────────────────────────────────────────────────

export interface ContextualActionsProps {
  /** Page bucket — one of the keys in the action catalogue. */
  page: ContextualPage;
  /** ID of the alert / case / rule / playbook the user is viewing. */
  entityId: string;
  /** Optional snapshot the LLM can read for grounding. Keep small. */
  entity?: Record<string, unknown> | null;
  /** Optional case correlation; recorded in agent logs. */
  caseId?: string | null;
  /**
   * Visual density.
   *   "pills"   — full label per button (default; good above the fold)
   *   "compact" — icon + short label, fits inside dense headers
   */
  variant?: 'pills' | 'compact';
  /** Extra classes for the outer wrapper. */
  className?: string;
  /** Optional eyebrow shown above the pills. */
  eyebrow?: string;
}

// ─── Action catalogue (with SWR cache) ──────────────────────────────────────

async function fetchCatalogue(): Promise<ContextualActionsCatalogue> {
  return contextualApi.listActions();
}

// ─── Main component ─────────────────────────────────────────────────────────

export function ContextualActions({
  page,
  entityId,
  entity,
  caseId,
  variant = 'pills',
  className,
  eyebrow,
}: ContextualActionsProps) {
  const { data: catalogue } = useSWR<ContextualActionsCatalogue>(
    'contextual-catalogue',
    fetchCatalogue,
    {
      // The catalogue is server-driven config. It rarely changes, so cache
      // aggressively across the session.
      revalidateOnFocus: false,
      revalidateIfStale: false,
      dedupingInterval: 60_000,
    },
  );

  const actions: ContextualActionDescriptor[] = useMemo(
    () => catalogue?.pages?.[page] ?? [],
    [catalogue, page],
  );

  // Active panel state
  const [activeAction, setActiveAction] = useState<string | null>(null);
  const [activeLabel, setActiveLabel] = useState<string>('');
  const [streaming, setStreaming] = useState(false);
  const [content, setContent] = useState('');
  const [headerFrame, setHeaderFrame] = useState<ContextualStreamFrame | null>(null);
  const [doneFrame, setDoneFrame] = useState<ContextualStreamFrame | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Reset all panel state on entity change so we never bleed responses across
  // alerts/cases.
  useEffect(() => {
    abortRef.current?.abort();
    setActiveAction(null);
    setActiveLabel('');
    setContent('');
    setHeaderFrame(null);
    setDoneFrame(null);
    setErrorMsg(null);
    setStreaming(false);
  }, [page, entityId]);

  const closePanel = useCallback(() => {
    abortRef.current?.abort();
    setActiveAction(null);
    setActiveLabel('');
    setContent('');
    setHeaderFrame(null);
    setDoneFrame(null);
    setErrorMsg(null);
    setStreaming(false);
  }, []);

  const runAction = useCallback(
    async (descriptor: ContextualActionDescriptor) => {
      // Cancel any in-flight stream before kicking off a new one.
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      setActiveAction(descriptor.key);
      setActiveLabel(descriptor.label);
      setContent('');
      setHeaderFrame(null);
      setDoneFrame(null);
      setErrorMsg(null);
      setStreaming(true);

      try {
        const response = await contextualApi.stream(
          {
            page,
            action: descriptor.key,
            entity_id: entityId,
            entity: entity ?? undefined,
            case_id: caseId ?? undefined,
          },
          controller.signal,
        );

        if (!response.ok || !response.body) {
          throw new Error(`Agent service responded ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        // NDJSON: one JSON object per line. Buffer across chunks so we don't
        // split a single object in half if the network rounds out a chunk
        // mid-line.
        // eslint-disable-next-line no-constant-condition
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          let newlineIdx = buffer.indexOf('\n');
          while (newlineIdx !== -1) {
            const line = buffer.slice(0, newlineIdx).trim();
            buffer = buffer.slice(newlineIdx + 1);
            newlineIdx = buffer.indexOf('\n');
            if (!line) continue;

            let frame: ContextualStreamFrame;
            try {
              frame = JSON.parse(line) as ContextualStreamFrame;
            } catch {
              continue;
            }

            if (frame.error) {
              setErrorMsg(frame.error);
              continue;
            }
            if (frame.title && !headerFrame) {
              setHeaderFrame(frame);
            }
            if (typeof frame.delta === 'string') {
              setContent((prev) => prev + frame.delta);
            }
            if (frame.done) {
              setDoneFrame(frame);
            }
          }
        }

        // Flush any trailing buffer (rare; backend always ends with newline)
        const trailing = buffer.trim();
        if (trailing) {
          try {
            const frame = JSON.parse(trailing) as ContextualStreamFrame;
            if (typeof frame.delta === 'string') {
              setContent((prev) => prev + frame.delta);
            }
            if (frame.done) setDoneFrame(frame);
          } catch {
            /* ignore */
          }
        }
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') return;
        setErrorMsg(
          err instanceof Error ? err.message : 'Contextual action failed',
        );
      } finally {
        setStreaming(false);
      }
    },
    [page, entityId, entity, caseId, headerFrame],
  );

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  if (actions.length === 0) {
    // Catalogue still loading or page not registered — render nothing so we
    // don't leak empty UI.
    return null;
  }

  return (
    <div className={clsx('space-y-2', className)}>
      {eyebrow ? (
        <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
          {eyebrow}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        {actions.map((descriptor) => {
          const active = activeAction === descriptor.key;
          return (
            <button
              key={descriptor.key}
              type="button"
              onClick={() => void runAction(descriptor)}
              disabled={streaming && active}
              title={descriptor.description}
              className={clsx(
                'inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors',
                active
                  ? 'border-violet-500/50 bg-violet-500/15 text-violet-100'
                  : 'border-slate-700/70 bg-slate-900/40 text-slate-200 hover:border-violet-500/40 hover:bg-violet-500/10 hover:text-violet-100',
                streaming && active && 'cursor-progress',
                variant === 'compact' && 'px-2.5 py-1',
              )}
            >
              <SparklesIcon className="h-3 w-3" />
              <span>{descriptor.label}</span>
              {streaming && active ? (
                <span className="ml-0.5 inline-flex h-2 w-2 animate-pulse rounded-full bg-violet-400" />
              ) : null}
            </button>
          );
        })}
      </div>

      {activeAction ? (
        <ContextualPanel
          title={headerFrame?.title ?? activeLabel}
          model={headerFrame?.model}
          fallback={Boolean(headerFrame?.fallback)}
          streaming={streaming}
          content={content}
          error={errorMsg}
          done={doneFrame}
          onClose={closePanel}
          onChainAction={(suggestion) => {
            const next = actions.find((a) => a.key === suggestion.action);
            if (next) void runAction(next);
          }}
        />
      ) : null}
    </div>
  );
}

// ─── Inline panel ───────────────────────────────────────────────────────────

interface ContextualPanelProps {
  title: string;
  model?: string;
  fallback: boolean;
  streaming: boolean;
  content: string;
  error: string | null;
  done: ContextualStreamFrame | null;
  onClose: () => void;
  onChainAction: (suggestion: ContextualSuggestion) => void;
}

function ContextualPanel({
  title,
  model,
  fallback,
  streaming,
  content,
  error,
  done,
  onClose,
  onChainAction,
}: ContextualPanelProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    if (!content) return;
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* ignore */
    }
  }, [content]);

  const confidence = done?.confidence;
  const suggestions = done?.suggestions ?? [];

  return (
    <div
      className={clsx(
        'rounded-xl border bg-slate-900/60 backdrop-blur-sm',
        error
          ? 'border-rose-500/40'
          : fallback
            ? 'border-amber-500/30'
            : 'border-violet-500/30',
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between gap-3 border-b border-slate-800/60 px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <SparklesIcon className="h-3.5 w-3.5 shrink-0 text-violet-300" />
          <span className="truncate text-sm font-semibold text-slate-100">
            {title}
          </span>
          {streaming ? (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-violet-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-violet-200">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-violet-400" />
              Thinking
            </span>
          ) : null}
          {fallback ? (
            <span
              title="Running without an LLM. Set OPENAI_API_KEY to enable real answers."
              className="inline-flex shrink-0 items-center gap-1 rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-amber-200"
            >
              Demo mode
            </span>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {model ? (
            <span className="hidden text-[10px] font-mono text-slate-500 sm:inline">
              {model}
            </span>
          ) : null}
          <button
            type="button"
            onClick={handleCopy}
            disabled={!content}
            title="Copy response"
            className="rounded-md p-1 text-slate-500 hover:bg-slate-800/60 hover:text-slate-200 disabled:opacity-30"
          >
            {copied ? <CheckIcon className="h-3.5 w-3.5" /> : <CopyIcon className="h-3.5 w-3.5" />}
          </button>
          <button
            type="button"
            onClick={onClose}
            title="Close"
            className="rounded-md p-1 text-slate-500 hover:bg-slate-800/60 hover:text-slate-200"
          >
            <XIcon className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="max-h-[480px] overflow-auto px-4 py-3">
        {error ? (
          <div className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
            <strong className="block text-xs uppercase tracking-wider text-rose-300">
              Contextual action failed
            </strong>
            <span>{error}</span>
          </div>
        ) : !content && streaming ? (
          <div className="space-y-2">
            <SkeletonBar width="80%" />
            <SkeletonBar width="65%" />
            <SkeletonBar width="92%" />
            <SkeletonBar width="40%" />
          </div>
        ) : (
          <Markdown text={content || '_No response yet._'} />
        )}
      </div>

      {/* Footer: confidence + suggestions */}
      {(suggestions.length > 0 || confidence !== undefined) && !error ? (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800/60 px-4 py-2.5">
          <div className="flex flex-wrap items-center gap-1.5">
            {suggestions.length > 0 ? (
              <span className="text-[11px] uppercase tracking-wider text-slate-500">
                Try next:
              </span>
            ) : null}
            {suggestions.map((suggestion) => (
              <button
                key={suggestion.label}
                type="button"
                onClick={() => onChainAction(suggestion)}
                disabled={!suggestion.action}
                className="rounded-full border border-slate-700/70 bg-slate-900/60 px-2.5 py-0.5 text-[11px] text-slate-200 hover:border-violet-500/40 hover:bg-violet-500/10 hover:text-violet-100 disabled:opacity-50"
              >
                {suggestion.label}
              </button>
            ))}
          </div>
          {confidence !== undefined ? (
            <span
              className="text-[11px] text-slate-500"
              title="Confidence the agent has in this response"
            >
              Confidence: {Math.round(confidence * 100)}%
            </span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

// ─── Lightweight markdown renderer ──────────────────────────────────────────
//
// We deliberately avoid pulling in `react-markdown` + `remark-gfm` for this
// surface — the LLM only emits a tight subset (headings, code blocks, lists,
// inline emphasis, links). A bespoke renderer keeps the bundle small and the
// output styled to match the rest of the AiSOC console.

function Markdown({ text }: { text: string }) {
  const blocks = useMemo(() => parseMarkdownBlocks(text), [text]);
  return (
    <div className="space-y-3 text-sm leading-relaxed text-slate-200">
      {blocks.map((block, idx) => {
        switch (block.type) {
          case 'h2':
            return (
              <h3 key={idx} className="text-sm font-semibold uppercase tracking-wider text-violet-200">
                {renderInline(block.text)}
              </h3>
            );
          case 'h3':
            return (
              <h4 key={idx} className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                {renderInline(block.text)}
              </h4>
            );
          case 'code':
            return (
              <pre
                key={idx}
                className="overflow-auto rounded-md border border-slate-800 bg-slate-950/80 p-3 text-xs leading-relaxed text-slate-200"
              >
                <code className={clsx('font-mono', block.language && `language-${block.language}`)}>
                  {block.text}
                </code>
              </pre>
            );
          case 'list':
            return (
              <ul key={idx} className="list-disc space-y-1 pl-5 text-sm text-slate-200">
                {block.items.map((item, i) => (
                  <li key={i}>{renderInline(item)}</li>
                ))}
              </ul>
            );
          case 'numbered':
            return (
              <ol key={idx} className="list-decimal space-y-1 pl-5 text-sm text-slate-200">
                {block.items.map((item, i) => (
                  <li key={i}>{renderInline(item)}</li>
                ))}
              </ol>
            );
          case 'p':
          default:
            return (
              <p key={idx} className="text-sm text-slate-200">
                {renderInline(block.text)}
              </p>
            );
        }
      })}
    </div>
  );
}

type MdBlock =
  | { type: 'h2'; text: string }
  | { type: 'h3'; text: string }
  | { type: 'p'; text: string }
  | { type: 'code'; text: string; language?: string }
  | { type: 'list'; items: string[] }
  | { type: 'numbered'; items: string[] };

function parseMarkdownBlocks(text: string): MdBlock[] {
  const lines = text.split('\n');
  const out: MdBlock[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (line.startsWith('```')) {
      const language = line.slice(3).trim() || undefined;
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      // Skip closing fence (or EOF)
      if (i < lines.length) i++;
      out.push({ type: 'code', text: codeLines.join('\n'), language });
      continue;
    }

    // Headings
    if (line.startsWith('## ')) {
      out.push({ type: 'h2', text: line.slice(3).trim() });
      i++;
      continue;
    }
    if (line.startsWith('### ')) {
      out.push({ type: 'h3', text: line.slice(4).trim() });
      i++;
      continue;
    }

    // Bullet list
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ''));
        i++;
      }
      out.push({ type: 'list', items });
      continue;
    }

    // Numbered list
    if (/^\s*\d+[.)]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+[.)]\s+/, ''));
        i++;
      }
      out.push({ type: 'numbered', items });
      continue;
    }

    // Paragraph: gather contiguous non-blank lines
    if (line.trim()) {
      const para: string[] = [line];
      i++;
      while (
        i < lines.length &&
        lines[i].trim() &&
        !lines[i].startsWith('## ') &&
        !lines[i].startsWith('### ') &&
        !lines[i].startsWith('```') &&
        !/^\s*[-*]\s+/.test(lines[i]) &&
        !/^\s*\d+[.)]\s+/.test(lines[i])
      ) {
        para.push(lines[i]);
        i++;
      }
      out.push({ type: 'p', text: para.join(' ') });
      continue;
    }

    // Blank line — skip
    i++;
  }

  return out;
}

function renderInline(text: string): ReactNode {
  // Escape-safe inline pass: split on the markdown delimiters in priority
  // order (code > bold > italic > link) so we don't double-process.
  const tokens: Array<{ type: 'text' | 'code' | 'bold' | 'link'; value: string; href?: string }> = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)]+\))/g;
  let lastIdx = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    if (match.index > lastIdx) {
      tokens.push({ type: 'text', value: text.slice(lastIdx, match.index) });
    }
    const m = match[0];
    if (m.startsWith('`')) {
      tokens.push({ type: 'code', value: m.slice(1, -1) });
    } else if (m.startsWith('**')) {
      tokens.push({ type: 'bold', value: m.slice(2, -2) });
    } else {
      const linkMatch = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(m);
      if (linkMatch) {
        tokens.push({ type: 'link', value: linkMatch[1], href: linkMatch[2] });
      } else {
        tokens.push({ type: 'text', value: m });
      }
    }
    lastIdx = match.index + m.length;
  }
  if (lastIdx < text.length) {
    tokens.push({ type: 'text', value: text.slice(lastIdx) });
  }

  return (
    <>
      {tokens.map((token, i) => {
        switch (token.type) {
          case 'code':
            return (
              <code
                key={i}
                className="rounded bg-slate-800/80 px-1 py-0.5 font-mono text-[12px] text-violet-200"
              >
                {token.value}
              </code>
            );
          case 'bold':
            return (
              <strong key={i} className="font-semibold text-slate-100">
                {token.value}
              </strong>
            );
          case 'link':
            return (
              <a
                key={i}
                href={token.href}
                target="_blank"
                rel="noreferrer"
                className="text-violet-300 underline-offset-2 hover:underline"
              >
                {token.value}
              </a>
            );
          default:
            return <span key={i}>{token.value}</span>;
        }
      })}
    </>
  );
}

// ─── Tiny inline icons (so we don't pull in a whole icon set) ───────────────

function SparklesIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <path d="M9 4l1.5 4.5L15 10l-4.5 1.5L9 16l-1.5-4.5L3 10l4.5-1.5z" />
      <path d="M18 14l.75 2.25L21 17l-2.25.75L18 20l-.75-2.25L15 17l2.25-.75z" />
    </svg>
  );
}

function CopyIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15V5a2 2 0 0 1 2-2h10" />
    </svg>
  );
}

function CheckIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function XIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}

function SkeletonBar({ width }: { width: string }) {
  return (
    <div
      className="h-3 animate-pulse rounded bg-slate-800/70"
      style={{ width }}
    />
  );
}
