'use client';

/**
 * ExplainDrawer
 * =============
 *
 * Right-edge slide-over that explains a single alert in OCSF + MITRE
 * terms. The drawer has *two* backends and prefers the richer one:
 *
 *   1. Structured (preferred) — `POST /api/v1/alerts/{id}/explain` on the
 *      API service. Returns a single JSON envelope with rule lineage,
 *      historical false-positive rate, MITRE technique cards, contributing
 *      events, suggested actions, and a deterministic-or-LLM summary.
 *      Used for the "what *is* this alert" answer + sidebar context.
 *   2. NDJSON stream (fallback) — `POST /api/v1/explain` on the agents
 *      service. Token-by-token typewriter. Used when (a) the structured
 *      endpoint 404s (older backend), (b) a non-429 error happens, or
 *      (c) the structured payload is missing a summary.
 *
 * 429 from the structured endpoint surfaces directly — both backends share
 * tenant rate-limit budget for LLM calls, so silently retrying with the
 * stream just doubles the spend and makes the rate-limit useless.
 *
 * Why a drawer instead of inline?
 * -------------------------------
 * The alert detail page is already dense. A drawer keeps the alert grid
 * intact while the analyst is still in the middle of reading the row, and
 * gives us room for ATT&CK technique cards (which want their own width).
 *
 * Streaming model (fallback path)
 * --------------------------------
 * Each line of the response body is one {@link ExplainStreamFrame}. The
 * drawer routes by `kind`:
 *
 *   - `section` opens a new section (summary / ocsf / mitre / evidence /
 *     next) so the renderer can show a heading even before any content
 *     has arrived. This avoids the "blank drawer for 800ms" flash.
 *   - `delta` (only for the summary) appends a token. Buffered into one
 *     state field so React doesn't re-render per word.
 *   - `ocsf`, `mitre`, `evidence`, `next_step` are typed records.
 *   - `done` closes the stream cleanly.
 *   - `error` aborts and shows the message.
 *
 * Cancellation
 * ------------
 * We use an `AbortController` that fires on close + on unmount. This
 * guarantees that closing the drawer also aborts an in-flight LLM call,
 * which is important when the user clicks Explain on the wrong alert and
 * immediately closes it.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  agentsApi,
  alertsApi,
  ApiError,
  type Alert,
  type AlertExplanation,
  type ContributingEvent,
  type ExplainEvidenceFrame,
  type ExplainMitreFrame,
  type ExplainNextStepFrame,
  type ExplainOcsfFrame,
  type ExplainStreamFrame,
  type HistoricalFpRate,
  type MitreTechniqueCard,
  type RuleLineage,
  type SuggestedAction,
} from '@/lib/api';
import { clsx } from 'clsx';

// ─── Props ───────────────────────────────────────────────────────────────────

export interface ExplainDrawerProps {
  /** Whether the drawer is currently visible. */
  open: boolean;
  /** Called when the user requests to close (overlay click, ESC, X). */
  onClose: () => void;
  /** Source alert. We pass the full record to the backend. */
  alert: Alert;
  /**
   * Optional callback when the user clicks "Run playbook" inside a
   * recommended next-step card. The parent owns the actual run logic so
   * the drawer stays presentational.
   */
  onRunPlaybook?: (playbookId: string) => void;
}

// ─── Internal state shape ────────────────────────────────────────────────────
//
// We keep everything keyed by section so frames can arrive in any order
// without breaking the render. (The backend sends them in canonical order
// today, but treating order as a hint not a contract makes this resilient
// when we layer caching or replay later.)
//
// Both backends populate the same shape; structured-only fields
// (`ruleLineage`, `historicalFpRate`, `suggestedActions`, `llm*`) are
// optional and simply don't render when absent.

interface DrawerState {
  status: 'idle' | 'loading' | 'streaming' | 'done' | 'error';
  /**
   * Which backend produced the data we're showing. Surfaced to the
   * analyst so "why is this faster/slower than usual?" has an answer,
   * and so QA can spot when the structured endpoint silently fell back.
   */
  source: 'structured' | 'stream' | null;
  error?: string;
  summary: string;
  ocsf?: ExplainOcsfFrame;
  mitre: ExplainMitreFrame[];
  evidence: ExplainEvidenceFrame[];
  nextSteps: ExplainNextStepFrame[];
  // ─── Structured-only ──────────────────────────────────────────────
  ruleLineage?: RuleLineage;
  historicalFpRate?: HistoricalFpRate;
  suggestedActions?: SuggestedAction[];
  /**
   * True when the structured endpoint actually called an LLM for the
   * summary; false when it returned the deterministic template (e.g.
   * because we're air-gapped or the tenant has no BYOK credentials).
   */
  llmUsed?: boolean;
  llmSource?: string;
  llmReason?: string;
  /**
   * ISO-8601 timestamp from the structured endpoint. Helps debug stale
   * cached payloads — though we don't cache today, the stamp is free
   * insurance for when we do.
   */
  generatedAt?: string;
}

const INITIAL: DrawerState = {
  status: 'idle',
  source: null,
  summary: '',
  mitre: [],
  evidence: [],
  nextSteps: [],
};

// ─── Component ───────────────────────────────────────────────────────────────

export function ExplainDrawer({
  open,
  onClose,
  alert,
  onRunPlaybook,
}: ExplainDrawerProps) {
  const [state, setState] = useState<DrawerState>(INITIAL);
  const abortRef = useRef<AbortController | null>(null);

  // The alert object we send to the backend. We strip large fields the
  // server doesn't need so the request stays lean.
  const alertPayload = useMemo(() => {
    const { rawEvent: _rawEvent, ...rest } = alert as Alert & {
      rawEvent?: unknown;
    };
    return rest as unknown as Record<string, unknown>;
  }, [alert]);

  /**
   * Stream explanation tokens from the agents service (NDJSON fallback
   * path). Mutates state in-place via the reducer so the UI gets a
   * typewriter effect. Resolves true on a clean `done`, false on error.
   *
   * The signal argument is a *shared* AbortController so cancelling the
   * drawer also cancels the in-flight `fetch` immediately — without it,
   * closing the drawer mid-LLM-call would still rack up tokens until
   * the model finished.
   */
  const runStream = useCallback(
    async (signal: AbortSignal): Promise<void> => {
      setState((s) => ({ ...s, status: 'loading', source: 'stream' }));

      const response = await agentsApi.explainStream(
        { alert: alertPayload, alertId: alert.id },
        signal,
      );

      if (!response.ok || !response.body) {
        throw new Error(`Explain endpoint returned HTTP ${response.status}`);
      }

      setState((s) => ({ ...s, status: 'streaming' }));

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      // NDJSON parse loop. Same pattern as ContextualActions.tsx — read
      // chunks, split on newlines, JSON.parse each line, ignore empty
      // lines. Buffering across chunks keeps us safe when a frame is
      // split mid-line by the network layer.
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let nl = buffer.indexOf('\n');
        while (nl !== -1) {
          const line = buffer.slice(0, nl).trim();
          buffer = buffer.slice(nl + 1);
          nl = buffer.indexOf('\n');
          if (!line) continue;

          let frame: ExplainStreamFrame;
          try {
            frame = JSON.parse(line) as ExplainStreamFrame;
          } catch {
            continue;
          }

          setState((s) => applyFrame(s, frame));
          if (frame.kind === 'error' || frame.kind === 'done') return;
        }
      }
    },
    [alert.id, alertPayload],
  );

  /**
   * Top-level loader. Tries the structured endpoint first, falls back
   * to the stream if it 404s or fails (but NOT on 429 — that's a real
   * answer the user needs to see). Always writes `INITIAL` first so a
   * second open doesn't show stale data from the previous alert.
   */
  const loadExplanation = useCallback(async () => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    setState({ ...INITIAL, status: 'loading' });

    // ── Attempt 1: structured endpoint ─────────────────────────────
    try {
      const payload = await alertsApi.explain(alert.id, ctrl.signal);
      // The drawer might have been closed while the request was in
      // flight — `request()` wraps AbortError into ApiError so we
      // can't rely on the exception. Check the signal explicitly.
      if (ctrl.signal.aborted) return;
      setState((s) => applyStructured(s, payload));
      return;
    } catch (err) {
      if (ctrl.signal.aborted) return;

      // 429 = rate limit. Surface directly. Falling back to the
      // streaming endpoint would (a) ignore the analyst's tenant
      // budget and (b) still get rate-limited on the agents service
      // anyway because both share LLM cost ledger.
      if (err instanceof ApiError && err.status === 429) {
        setState((s) => ({
          ...s,
          status: 'error',
          source: 'structured',
          error:
            'Rate limit reached for AI explanations. Please try again in a moment.',
        }));
        return;
      }

      // 404 / 500 / network → fall through to the stream. We log so
      // ops can see when the structured backend is down (and keep a
      // breadcrumb in the user's network tab if they peek).
      // eslint-disable-next-line no-console
      console.warn(
        '[ExplainDrawer] Structured endpoint unavailable, falling back to stream:',
        err,
      );
    }

    // ── Attempt 2: NDJSON stream ───────────────────────────────────
    try {
      await runStream(ctrl.signal);
    } catch (err) {
      if (ctrl.signal.aborted) return;
      if ((err as { name?: string })?.name === 'AbortError') return;
      setState((s) => ({
        ...s,
        status: 'error',
        source: 'stream',
        error:
          err instanceof Error
            ? err.message
            : 'Failed to load explanation.',
      }));
    }
  }, [alert.id, runStream]);

  // Open / close lifecycle. Re-fetches on every open so the drawer is
  // always fresh — alert state (severity, disposition, etc.) changes
  // between opens, and the FP rate could drift even within a session.
  useEffect(() => {
    if (!open) {
      abortRef.current?.abort();
      return;
    }
    void loadExplanation();
    return () => {
      abortRef.current?.abort();
    };
  }, [open, loadExplanation]);

  // ESC to close.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Click-to-close overlay. */}
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="flex-1 bg-black/60 backdrop-blur-sm cursor-default"
      />

      {/* Drawer panel. */}
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Explain alert"
        className="w-full max-w-2xl h-full bg-gray-950 border-l border-gray-800 shadow-2xl flex flex-col"
      >
        <DrawerHeader
          alert={alert}
          status={state.status}
          source={state.source}
          onClose={onClose}
          onRetry={state.status === 'error' ? loadExplanation : undefined}
        />

        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
          {state.status === 'error' && (
            <ErrorBanner message={state.error || 'Unknown error'} />
          )}

          <SummarySection text={state.summary} status={state.status} />

          {/* ── Structured-only sections ── */}
          {state.ruleLineage && (
            <RuleLineageSection lineage={state.ruleLineage} />
          )}

          {state.historicalFpRate && (
            <FpRateSection fpr={state.historicalFpRate} />
          )}

          {state.ocsf && <OcsfSection frame={state.ocsf} />}

          {state.mitre.length > 0 && (
            <MitreSection cards={state.mitre} />
          )}

          {state.evidence.length > 0 && (
            <EvidenceSection items={state.evidence} />
          )}

          {state.suggestedActions && state.suggestedActions.length > 0 && (
            <SuggestedActionsSection
              actions={state.suggestedActions}
              onRunPlaybook={onRunPlaybook}
            />
          )}

          {state.nextSteps.length > 0 && (
            <NextStepsSection
              steps={state.nextSteps}
              onRunPlaybook={onRunPlaybook}
            />
          )}

          {/* LLM disclosure footer (structured only). Tells the user
              whether prose was actually LLM-generated, with the source
              and (if not) the reason. Required for the "audit my AI
              decisions" workflow. */}
          {state.source === 'structured' && state.llmUsed !== undefined && (
            <LlmDisclosure
              used={state.llmUsed}
              source={state.llmSource}
              reason={state.llmReason}
              generatedAt={state.generatedAt}
            />
          )}

          {state.status === 'done' && state.source !== 'structured' && (
            <div className="text-xs text-gray-500 text-center pt-2">
              Generated by AiSOC. Always verify before taking action.
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}

// ─── Reducers ────────────────────────────────────────────────────────────────

function applyFrame(state: DrawerState, frame: ExplainStreamFrame): DrawerState {
  switch (frame.kind) {
    case 'section':
      // Sections themselves carry no content — we render the heading
      // implicitly when their array becomes non-empty. Nothing to merge.
      return state;
    case 'delta':
      return { ...state, summary: state.summary + frame.text };
    case 'ocsf':
      return { ...state, ocsf: frame };
    case 'mitre':
      // Dedupe by ID so a re-emitted card doesn't double-render.
      if (state.mitre.some((m) => m.id === frame.id)) return state;
      return { ...state, mitre: [...state.mitre, frame] };
    case 'evidence':
      return { ...state, evidence: [...state.evidence, frame] };
    case 'next_step':
      return { ...state, nextSteps: [...state.nextSteps, frame] };
    case 'done':
      return { ...state, status: 'done' };
    case 'error':
      return { ...state, status: 'error', error: frame.error };
    default:
      return state;
  }
}

/**
 * Hydrate the drawer state from a single structured response. We
 * translate MITRE technique cards into the same shape the streaming
 * code path produces (`ExplainMitreFrame`) so MitreSection doesn't need
 * to know which backend served it. Same trick for evidence — a normal
 * ContributingEvent maps cleanly onto an ExplainEvidenceFrame.
 */
function applyStructured(
  state: DrawerState,
  payload: AlertExplanation,
): DrawerState {
  return {
    ...state,
    status: 'done',
    source: 'structured',
    error: undefined,
    summary: payload.summary,
    // OCSF isn't part of the structured payload yet (it lives on the
    // alert record itself; the stream synthesizes it). Leave undefined
    // and let MitreSection/EvidenceSection carry the load.
    ocsf: undefined,
    mitre: payload.mitre_techniques.map(toMitreFrame),
    evidence: payload.contributing_events.map(toEvidenceFrame),
    // Suggested actions render in their own section — keep nextSteps
    // empty so we don't double-show.
    nextSteps: [],
    ruleLineage: payload.rule_lineage,
    historicalFpRate: payload.historical_fp_rate,
    suggestedActions: payload.suggested_actions,
    llmUsed: payload.llm_used,
    llmSource: payload.llm_source,
    llmReason: payload.llm_reason,
    generatedAt: payload.generated_at,
  };
}

/** Adapt a structured MITRE card into the streaming frame shape. */
function toMitreFrame(card: MitreTechniqueCard): ExplainMitreFrame {
  return {
    kind: 'mitre',
    id: card.id,
    name: card.name,
    tactic_names: card.tactic_names,
    description: card.description,
    url: card.url,
    // Structured backend only emits cards it actually resolved, so
    // `found` is implicitly true. The streaming backend uses this flag
    // to flag stub cards when the corpus is missing.
    found: true,
  };
}

/** Adapt a structured contributing event into the streaming frame shape. */
function toEvidenceFrame(ev: ContributingEvent): ExplainEvidenceFrame {
  return {
    kind: 'evidence',
    label: ev.label,
    value: ev.value,
    // The streaming frame requires `annotation`; default to empty
    // string so EvidenceSection can keep its `if (annotation)` guards.
    annotation: ev.annotation ?? '',
  };
}

// ─── Subcomponents ───────────────────────────────────────────────────────────

function DrawerHeader({
  alert,
  status,
  source,
  onClose,
  onRetry,
}: {
  alert: Alert;
  status: DrawerState['status'];
  source: DrawerState['source'];
  onClose: () => void;
  onRetry?: () => void;
}) {
  return (
    <div className="flex items-start justify-between border-b border-gray-800 px-6 py-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-semibold uppercase tracking-wider text-blue-400">
            Explain
          </span>
          <StatusBadge status={status} />
          {source && <SourceBadge source={source} />}
        </div>
        <h2 className="text-lg font-semibold text-gray-100 truncate">
          {alert.title}
        </h2>
        <p className="text-xs text-gray-400 mt-0.5">
          {alert.source} · {alert.severity} · {alert.id}
        </p>
      </div>

      <div className="flex items-center gap-2 ml-4">
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="text-xs px-3 py-1.5 rounded-md bg-gray-800 text-gray-200 hover:bg-gray-700 transition"
          >
            Retry
          </button>
        )}
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="text-gray-400 hover:text-gray-100 transition p-1"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        </button>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: DrawerState['status'] }) {
  const map: Record<DrawerState['status'], { label: string; cls: string }> = {
    idle: { label: 'Idle', cls: 'bg-gray-500/10 text-gray-400 ring-gray-500/20' },
    loading: {
      label: 'Loading…',
      cls: 'bg-blue-500/10 text-blue-300 ring-blue-500/20',
    },
    streaming: {
      label: 'Streaming',
      cls: 'bg-blue-500/10 text-blue-300 ring-blue-500/20',
    },
    done: {
      label: 'Done',
      cls: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20',
    },
    error: { label: 'Error', cls: 'bg-red-500/10 text-red-400 ring-red-500/20' },
  };
  const { label, cls } = map[status];
  return (
    <span
      className={clsx(
        'text-[10px] font-mono px-2 py-0.5 rounded ring-1 ring-inset',
        cls,
      )}
    >
      {label}
    </span>
  );
}

/**
 * Tiny badge showing which backend served the explanation. Useful for
 * QA ("did the structured endpoint actually fire?") and for analysts
 * who notice the structured payload is richer than the streamed one.
 * Hidden in idle state so the chrome stays clean before the first call.
 */
function SourceBadge({ source }: { source: 'structured' | 'stream' }) {
  if (source === 'structured') {
    return (
      <span
        className="text-[10px] font-mono px-2 py-0.5 rounded ring-1 ring-inset bg-purple-500/10 text-purple-300 ring-purple-500/20"
        title="Structured one-shot endpoint (richer context, no token streaming)"
      >
        Structured
      </span>
    );
  }
  return (
    <span
      className="text-[10px] font-mono px-2 py-0.5 rounded ring-1 ring-inset bg-amber-500/10 text-amber-300 ring-amber-500/20"
      title="NDJSON streaming fallback (structured endpoint unavailable)"
    >
      Stream
    </span>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-300">
      {message}
    </div>
  );
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 mb-2">
      {children}
    </h3>
  );
}

function SummarySection({
  text,
  status,
}: {
  text: string;
  status: DrawerState['status'];
}) {
  const showCursor = status === 'loading' || status === 'streaming';
  return (
    <section>
      <SectionHeading>What happened</SectionHeading>
      <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">
        {text || (status === 'loading' ? 'Generating explanation…' : '—')}
        {showCursor && text && (
          <span className="inline-block w-1.5 h-4 ml-0.5 bg-blue-400 animate-pulse align-middle" />
        )}
      </p>
    </section>
  );
}

function OcsfSection({ frame }: { frame: ExplainOcsfFrame }) {
  const hasFields = Object.keys(frame.fields || {}).length > 0;
  return (
    <section>
      <SectionHeading>OCSF mapping</SectionHeading>
      <div className="rounded-md border border-gray-800 bg-gray-900/60 p-4 space-y-2">
        <div className="flex flex-wrap gap-3 text-xs">
          <Tag label="Category" value={`${frame.category} (${frame.category_uid})`} />
          <Tag label="Class" value={`${frame.class} (${frame.class_uid})`} />
          <Tag label="Activity" value={frame.activity} />
        </div>
        {hasFields && (
          <dl className="grid grid-cols-[max-content,1fr] gap-x-3 gap-y-1 text-xs pt-2 border-t border-gray-800/80">
            {Object.entries(frame.fields).map(([k, v]) => (
              <FieldRow key={k} label={k} value={String(v)} />
            ))}
          </dl>
        )}
      </div>
    </section>
  );
}

function MitreSection({ cards }: { cards: ExplainMitreFrame[] }) {
  return (
    <section>
      <SectionHeading>MITRE ATT&CK</SectionHeading>
      <div className="space-y-2">
        {cards.map((c) => (
          <a
            key={c.id}
            href={c.url}
            target="_blank"
            rel="noreferrer noopener"
            className="block rounded-md border border-purple-500/20 bg-purple-500/5 p-3 hover:bg-purple-500/10 transition"
          >
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-mono text-purple-300 bg-purple-500/15 px-2 py-0.5 rounded">
                {c.id}
              </span>
              <span className="text-sm font-medium text-gray-100">{c.name}</span>
              {!c.found && (
                <span className="text-[10px] text-amber-400 ml-auto">
                  corpus unavailable
                </span>
              )}
            </div>
            {c.tactic_names.length > 0 && (
              <div className="text-xs text-gray-400 mb-1">
                Tactics: {c.tactic_names.join(', ')}
              </div>
            )}
            {c.description && (
              <p className="text-xs text-gray-300 leading-relaxed">
                {c.description}
              </p>
            )}
          </a>
        ))}
      </div>
    </section>
  );
}

function EvidenceSection({ items }: { items: ExplainEvidenceFrame[] }) {
  return (
    <section>
      <SectionHeading>Key evidence</SectionHeading>
      <ul className="space-y-1.5">
        {items.map((e, i) => (
          <li
            key={`${e.label}-${i}`}
            className="flex items-baseline gap-3 text-sm"
          >
            <span className="text-xs text-gray-500 min-w-[100px]">
              {e.label}
            </span>
            <span className="font-mono text-gray-100 break-all">
              {e.value}
            </span>
            {e.annotation && (
              <span className="text-xs text-gray-400 ml-auto">
                {e.annotation}
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

function NextStepsSection({
  steps,
  onRunPlaybook,
}: {
  steps: ExplainNextStepFrame[];
  onRunPlaybook?: (playbookId: string) => void;
}) {
  return (
    <section>
      <SectionHeading>Next steps</SectionHeading>
      <div className="space-y-2">
        {steps.map((s, i) => (
          <div
            key={`${s.title}-${i}`}
            className="rounded-md border border-gray-800 bg-gray-900/60 p-3"
          >
            <div className="flex items-start justify-between gap-2 mb-1">
              <h4 className="text-sm font-medium text-gray-100">{s.title}</h4>
              {s.playbook_id && onRunPlaybook && (
                <button
                  type="button"
                  onClick={() => onRunPlaybook(s.playbook_id!)}
                  className="text-xs px-2.5 py-1 rounded bg-blue-500/15 text-blue-300 hover:bg-blue-500/25 ring-1 ring-inset ring-blue-500/30 transition"
                >
                  Run playbook
                </button>
              )}
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">
              {s.rationale}
            </p>
            {s.playbook_id && (
              <div className="text-[10px] font-mono text-gray-500 mt-1">
                {s.playbook_id}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

// ─── Structured-only sections ────────────────────────────────────────────────

/**
 * Show which detection rule fired, with provenance. Confidence here is
 * about *the lineage match itself* (did we identify the right rule?),
 * not the rule's own confidence score. We split the two so analysts
 * can trust the rule-card description even when the match is fuzzy.
 *
 * `match_method=none` (no match at all) renders a soft empty state
 * rather than a missing section, so the absence is explicit.
 */
function RuleLineageSection({ lineage }: { lineage: RuleLineage }) {
  const confColor = {
    high: 'text-emerald-400 ring-emerald-500/20 bg-emerald-500/10',
    medium: 'text-amber-400 ring-amber-500/20 bg-amber-500/10',
    low: 'text-orange-400 ring-orange-500/20 bg-orange-500/10',
  }[lineage.confidence];

  if (lineage.match_method === 'none' || !lineage.rule_id) {
    return (
      <section>
        <SectionHeading>Detection rule</SectionHeading>
        <div className="rounded-md border border-gray-800 bg-gray-900/40 p-3 text-xs text-gray-500">
          No matching rule could be identified for this alert. The signal
          may have come from an ad-hoc query or a deprecated rule.
        </div>
      </section>
    );
  }

  return (
    <section>
      <SectionHeading>Detection rule</SectionHeading>
      <div className="rounded-md border border-gray-800 bg-gray-900/60 p-3 space-y-2">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <h4 className="text-sm font-medium text-gray-100 truncate">
              {lineage.rule_name || 'Unnamed rule'}
            </h4>
            <div className="text-[10px] font-mono text-gray-500 mt-0.5 truncate">
              {lineage.rule_id}
            </div>
          </div>
          <span
            className={clsx(
              'shrink-0 text-[10px] font-mono px-2 py-0.5 rounded ring-1 ring-inset',
              confColor,
            )}
            title={`Match method: ${lineage.match_method}`}
          >
            {lineage.confidence} confidence
          </span>
        </div>
        {lineage.rule_description && (
          <p className="text-xs text-gray-300 leading-relaxed">
            {lineage.rule_description}
          </p>
        )}
        <div className="flex flex-wrap gap-3 text-[11px] pt-1 border-t border-gray-800/80">
          {lineage.rule_severity && (
            <Tag label="Severity" value={lineage.rule_severity} />
          )}
          {lineage.rule_status && (
            <Tag label="Status" value={lineage.rule_status} />
          )}
          {lineage.rule_language && (
            <Tag label="Language" value={lineage.rule_language} />
          )}
          {lineage.rule_confidence !== null && (
            <Tag
              label="Rule confidence"
              value={`${lineage.rule_confidence}%`}
            />
          )}
          <Tag
            label="Source"
            value={lineage.is_builtin ? 'built-in' : 'custom'}
          />
          <Tag label="Matched via" value={lineage.match_method} />
        </div>
      </div>
    </section>
  );
}

/**
 * Render the live false-positive rate for the matched rule. The scope
 * field tells the user *what slice* the rate covers — sometimes the
 * rule itself doesn't have enough samples and we fall back to the
 * category or technique. Showing this honestly prevents a 0/3 sample
 * "0% FP rate!" misread.
 */
function FpRateSection({ fpr }: { fpr: HistoricalFpRate }) {
  const pct = (fpr.fp_rate * 100).toFixed(1);
  // Color the rate so high-FP rules pop. Thresholds chosen to match the
  // alert-reduction benchmark page (≥30% = red, ≥10% = amber).
  const rateColor =
    fpr.fp_rate >= 0.3
      ? 'text-red-400'
      : fpr.fp_rate >= 0.1
      ? 'text-amber-400'
      : 'text-emerald-400';
  // Sample size gating: <5 samples is statistically meaningless, warn.
  const lowSample = fpr.sample_size < 5;
  return (
    <section>
      <SectionHeading>Historical false-positive rate</SectionHeading>
      <div className="rounded-md border border-gray-800 bg-gray-900/60 p-3 space-y-1.5">
        <div className="flex items-baseline gap-3">
          <span className={clsx('text-2xl font-semibold tabular-nums', rateColor)}>
            {pct}%
          </span>
          <span className="text-xs text-gray-400">
            {fpr.false_positives} of {fpr.sample_size} resolved as FP
          </span>
          {lowSample && (
            <span className="text-[10px] text-amber-300 ml-auto">
              low-sample
            </span>
          )}
        </div>
        <div className="text-[11px] text-gray-500">{fpr.notes}</div>
        <div className="text-[10px] font-mono text-gray-600">
          scope={fpr.scope} · last {fpr.lookback_days}d
        </div>
      </div>
    </section>
  );
}

/**
 * Render deterministic suggested next steps from the structured
 * endpoint. Mirrors NextStepsSection but uses the priority field to
 * sort/color, since structured actions are hand-curated.
 */
function SuggestedActionsSection({
  actions,
  onRunPlaybook,
}: {
  actions: SuggestedAction[];
  onRunPlaybook?: (playbookId: string) => void;
}) {
  const priorityOrder = { immediate: 0, soon: 1, fyi: 2 } as const;
  const sorted = [...actions].sort(
    (a, b) => priorityOrder[a.priority] - priorityOrder[b.priority],
  );
  const priorityChip: Record<SuggestedAction['priority'], string> = {
    immediate: 'bg-red-500/15 text-red-300 ring-red-500/30',
    soon: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
    fyi: 'bg-gray-500/15 text-gray-400 ring-gray-500/30',
  };
  return (
    <section>
      <SectionHeading>Suggested actions</SectionHeading>
      <div className="space-y-2">
        {sorted.map((a, i) => (
          <div
            key={`${a.title}-${i}`}
            className="rounded-md border border-gray-800 bg-gray-900/60 p-3"
          >
            <div className="flex items-start justify-between gap-2 mb-1">
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className={clsx(
                    'shrink-0 text-[10px] font-mono px-2 py-0.5 rounded ring-1 ring-inset uppercase',
                    priorityChip[a.priority],
                  )}
                >
                  {a.priority}
                </span>
                <h4 className="text-sm font-medium text-gray-100 truncate">
                  {a.title}
                </h4>
              </div>
              {a.playbook_id && onRunPlaybook && (
                <button
                  type="button"
                  onClick={() => onRunPlaybook(a.playbook_id!)}
                  className="shrink-0 text-xs px-2.5 py-1 rounded bg-blue-500/15 text-blue-300 hover:bg-blue-500/25 ring-1 ring-inset ring-blue-500/30 transition"
                >
                  Run playbook
                </button>
              )}
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">
              {a.rationale}
            </p>
            {a.playbook_id && (
              <div className="text-[10px] font-mono text-gray-500 mt-1">
                {a.playbook_id}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

/**
 * Disclosure footer for the structured endpoint. Required for
 * compliance: any LLM-generated text must be flagged as such, and
 * non-LLM (deterministic fallback) text must be flagged so reviewers
 * know it's templated. The reason field surfaces *why* the LLM was
 * skipped (air-gap policy, no BYOK, budget exhausted, etc.).
 */
function LlmDisclosure({
  used,
  source,
  reason,
  generatedAt,
}: {
  used: boolean;
  source?: string;
  reason?: string;
  generatedAt?: string;
}) {
  const ts = generatedAt
    ? new Date(generatedAt).toLocaleString(undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
      })
    : null;
  return (
    <div className="text-[11px] text-gray-500 border-t border-gray-800/80 pt-3 space-y-0.5">
      <div className="flex items-center gap-2">
        <span
          className={clsx(
            'inline-block w-1.5 h-1.5 rounded-full',
            used ? 'bg-emerald-400' : 'bg-amber-400',
          )}
        />
        {used ? (
          <span>
            Summary generated by LLM
            {source ? ` (source: ${source})` : ''}.
          </span>
        ) : (
          <span>
            Summary is a deterministic template
            {reason ? ` — ${reason}` : ''}.
          </span>
        )}
      </div>
      {ts && <div className="font-mono text-gray-600">Generated {ts}</div>}
      <div className="pt-1">
        Generated by AiSOC. Always verify before taking action.
      </div>
    </div>
  );
}

// ─── Tiny presentational atoms ───────────────────────────────────────────────

function Tag({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-200 font-medium">{value}</span>
    </div>
  );
}

function FieldRow({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-gray-500 font-mono">{label}</dt>
      <dd className="text-gray-200 font-mono break-all">{value}</dd>
    </>
  );
}
