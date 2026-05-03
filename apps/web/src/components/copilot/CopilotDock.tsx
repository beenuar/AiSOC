'use client';

/**
 * Floating AI Copilot dock.
 *
 * A persistent bottom-right launcher that opens a compact chat panel without
 * leaving the current page. Reuses `copilotApi` for real calls and falls back
 * to a deterministic demo reply when the backend is unreachable.
 *
 * The full-page experience lives at `/copilot` (CopilotView). This dock is
 * the "ambient" surface — quick questions, scoped to whatever the analyst is
 * currently looking at (we capture `pathname` as `context.page`).
 */

import { useEffect, useRef, useState } from 'react';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { clsx } from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';
import { copilotApi, type CopilotMessage } from '@/lib/api';

const QUICK_PROMPTS = [
  'Summarize critical alerts in the last 24h.',
  'Investigate the host most at risk right now.',
  'Which detection rules are noisiest this week?',
];

function demoReply(prompt: string, page: string): CopilotMessage {
  const content =
    `**Demo reply** — the LLM backend is offline, so this is a stub.\n\n` +
    `Page context: \`${page}\`\n\n` +
    `> ${prompt}`;
  return {
    id: `demo-${Date.now()}`,
    role: 'assistant',
    content,
    createdAt: new Date().toISOString(),
    suggestions: [
      'Open AI Copilot',
      'Show me the top critical alerts.',
    ],
  };
}

export function CopilotDock() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const [demoMode, setDemoMode] = useState(false);
  const pathname = usePathname() ?? '/';
  const scrollerRef = useRef<HTMLDivElement>(null);

  // Hide the dock on the dedicated /copilot page — it would just duplicate UI.
  const onCopilotPage = pathname.startsWith('/copilot');

  // Keyboard shortcut: ⌘J / Ctrl+J toggles the dock.
  // (⌘K is reserved for the global command palette.)
  // We also listen for an `aisoc:open-copilot` window event so the palette
  // can open the dock without prop drilling.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const isToggle =
        (e.metaKey && e.key.toLowerCase() === 'j') ||
        (e.ctrlKey && e.key.toLowerCase() === 'j');
      if (isToggle) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
      if (e.key === 'Escape' && open) setOpen(false);
    };
    const onOpen = () => setOpen(true);
    window.addEventListener('keydown', onKey);
    window.addEventListener('aisoc:open-copilot', onOpen);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('aisoc:open-copilot', onOpen);
    };
  }, [open]);

  // Auto-scroll on new messages.
  useEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length, sending, open]);

  if (onCopilotPage) return null;

  const send = async (prompt: string) => {
    const trimmed = prompt.trim();
    if (!trimmed || sending) return;

    const userMsg: CopilotMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: trimmed,
      createdAt: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setSending(true);

    try {
      const res = await copilotApi.chat({
        conversationId,
        message: trimmed,
        context: { page: pathname },
      });
      setConversationId(res.conversationId);
      setMessages((prev) => [...prev, res.reply]);
      setDemoMode(false);
    } catch {
      setMessages((prev) => [...prev, demoReply(trimmed, pathname)]);
      setDemoMode(true);
    } finally {
      setSending(false);
    }
  };

  return (
    <>
      {/* Launcher (bottom-right) */}
      <AnimatePresence>
        {!open && (
          <motion.button
            key="launcher"
            initial={{ opacity: 0, scale: 0.9, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 12 }}
            onClick={() => setOpen(true)}
            className="fixed bottom-5 right-5 z-40 flex items-center gap-2 rounded-full bg-emerald-500 px-4 py-3 text-sm font-semibold text-emerald-950 shadow-lg shadow-emerald-900/30 transition-colors hover:bg-emerald-400"
            aria-label="Open AI Copilot"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09Z"
              />
            </svg>
            Ask Copilot
            <kbd className="rounded bg-emerald-900/30 px-1.5 py-0.5 text-[10px] font-mono text-emerald-100">
              ⌘J
            </kbd>
          </motion.button>
        )}
      </AnimatePresence>

      {/* Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            key="panel"
            initial={{ opacity: 0, y: 24, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 24, scale: 0.98 }}
            transition={{ duration: 0.18 }}
            className="fixed bottom-5 right-5 z-40 flex h-[32rem] w-[24rem] max-w-[calc(100vw-2.5rem)] flex-col overflow-hidden rounded-2xl border border-slate-800/80 bg-slate-900/95 shadow-2xl shadow-black/40 backdrop-blur"
            role="dialog"
            aria-label="AI Copilot"
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-800/80 px-3 py-2">
              <div className="flex items-center gap-2">
                <span className="flex h-7 w-7 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-300">
                  ⌬
                </span>
                <div>
                  <p className="text-sm font-semibold text-white">AI Copilot</p>
                  <p className="text-[11px] text-slate-400">
                    {demoMode ? 'Demo mode (offline)' : 'Connected'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <Link
                  href="/copilot"
                  className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-white"
                  title="Open full page"
                  aria-label="Open Copilot full page"
                >
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.75 3.75v4.5m0-4.5h4.5m-4.5 0L9 9M3.75 20.25v-4.5m0 4.5h4.5m-4.5 0L9 15M20.25 3.75h-4.5m4.5 0v4.5m0-4.5L15 9m5.25 11.25h-4.5m4.5 0v-4.5m0 4.5L15 15" />
                  </svg>
                </Link>
                <button
                  onClick={() => setOpen(false)}
                  className="rounded-md p-1.5 text-slate-400 transition-colors hover:bg-slate-800 hover:text-white"
                  aria-label="Close Copilot"
                >
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18 18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Thread */}
            <div ref={scrollerRef} className="min-h-0 flex-1 overflow-y-auto p-3">
              {messages.length === 0 ? (
                <div className="flex h-full flex-col justify-center">
                  <p className="px-1 text-xs text-slate-400">
                    Ask anything about your environment. I have your alerts,
                    cases, hosts, users, and detection rules.
                  </p>
                  <ul className="mt-3 space-y-1">
                    {QUICK_PROMPTS.map((p) => (
                      <li key={p}>
                        <button
                          onClick={() => void send(p)}
                          className="w-full rounded-md border border-slate-800 bg-slate-900/60 px-3 py-2 text-left text-xs text-slate-200 transition-colors hover:border-emerald-500/40 hover:bg-slate-800/60"
                        >
                          {p}
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <ul className="space-y-3">
                  {messages.map((m) => (
                    <li
                      key={m.id}
                      className={clsx(
                        'flex',
                        m.role === 'user' ? 'justify-end' : 'justify-start',
                      )}
                    >
                      <div
                        className={clsx(
                          'max-w-[85%] whitespace-pre-wrap rounded-2xl px-3 py-2 text-sm',
                          m.role === 'user'
                            ? 'bg-emerald-500/15 text-white ring-1 ring-emerald-500/30'
                            : 'bg-slate-800/70 text-slate-100 ring-1 ring-slate-700/60',
                        )}
                      >
                        {m.content}
                        {m.suggestions && m.suggestions.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {m.suggestions.map((s, idx) =>
                              s.startsWith('Open AI Copilot') ? (
                                <Link
                                  key={idx}
                                  href="/copilot"
                                  className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-200 transition-colors hover:bg-emerald-500/20"
                                >
                                  {s} →
                                </Link>
                              ) : (
                                <button
                                  key={idx}
                                  onClick={() => void send(s)}
                                  className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] text-emerald-200 transition-colors hover:bg-emerald-500/20"
                                >
                                  {s}
                                </button>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                  {sending && (
                    <li className="flex justify-start">
                      <div className="rounded-2xl bg-slate-800/70 px-3 py-2 ring-1 ring-slate-700/60">
                        <span className="inline-flex items-center gap-1">
                          {[0, 1, 2].map((i) => (
                            <motion.span
                              key={i}
                              className="block h-1.5 w-1.5 rounded-full bg-slate-400"
                              animate={{ opacity: [0.2, 1, 0.2] }}
                              transition={{
                                duration: 1.1,
                                repeat: Infinity,
                                delay: i * 0.18,
                              }}
                            />
                          ))}
                        </span>
                      </div>
                    </li>
                  )}
                </ul>
              )}
            </div>

            {/* Composer */}
            <div className="border-t border-slate-800/80 p-2">
              <div className="flex items-end gap-2 rounded-xl border border-slate-700/70 bg-slate-950/40 p-1.5 focus-within:border-emerald-500/50">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      void send(input);
                    }
                  }}
                  rows={1}
                  placeholder="Ask Copilot…"
                  className="flex-1 resize-none bg-transparent px-2 py-1.5 text-sm text-slate-100 placeholder-slate-500 outline-none"
                />
                <button
                  onClick={() => void send(input)}
                  disabled={!input.trim() || sending}
                  className={clsx(
                    'flex-none rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors',
                    input.trim() && !sending
                      ? 'bg-emerald-500 text-emerald-950 hover:bg-emerald-400'
                      : 'bg-slate-800 text-slate-500',
                  )}
                  aria-label="Send"
                >
                  ↑
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
