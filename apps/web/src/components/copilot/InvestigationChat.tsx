'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

type MessageRole = 'user' | 'assistant' | 'system';

interface ChatMessage {
  id: string;
  role: MessageRole;
  content: string;
  timestamp: string;
}

interface SummaryArtifact {
  artifactId: string;
  summaryMarkdown: string;
  closedAt: string;
}

const QUICK_ACTIONS = [
  'Investigate Alert',
  'Summarize Case',
  'Find IOCs',
  'Check Reputation',
] as const;

const MOCK_RESPONSES: Record<string, string> = {
  'investigate alert':
    'Analyzing alert ALT-4092... Identified lateral movement from 10.0.3.17 to DC01. ' +
    'The source host has 3 prior alerts in the last 48h. ATT&CK mapping: T1021.002 (SMB/Admin Shares). ' +
    'Recommend isolating the host and resetting credentials for svc-backup.',
  'summarize case':
    'Case CS-2187 Summary:\n' +
    '- 7 correlated alerts across 3 hosts\n' +
    '- Timeline: initial access at 02:14 UTC, privilege escalation at 02:31 UTC, exfil attempt at 03:05 UTC\n' +
    '- Affected users: j.harlow, svc-backup\n' +
    '- Current status: containment in progress, 2 hosts isolated',
  'find iocs':
    'Found 3 related IOCs across 2 tenants:\n' +
    '1. IP 198.51.100.47 — C2 callback (confidence: 92%)\n' +
    '2. Hash e3b0c442...b855 — LockBit dropper (confidence: 95%)\n' +
    '3. Domain secure-login.example-phish.com — credential harvesting (confidence: 88%)\n\n' +
    'All three match STIX indicators published in the last 24h.',
  'check reputation':
    'Reputation check for 198.51.100.47:\n' +
    '- VirusTotal: 14/87 engines flagged malicious\n' +
    '- AbuseIPDB: reported 23 times, confidence 91%\n' +
    '- First seen: 2025-04-12, Last seen: active\n' +
    '- Associated campaigns: APT-42, Operation ShadowGate\n' +
    '- Recommendation: block at perimeter immediately',
};

function getMockResponse(input: string): string {
  const lower = input.toLowerCase();
  for (const [key, response] of Object.entries(MOCK_RESPONSES)) {
    if (lower.includes(key)) return response;
  }
  return (
    `Analyzing your query: "${input}"\n\n` +
    'Found 3 related IOCs across 2 tenants. Cross-referencing with MITRE ATT&CK framework... ' +
    'Identified techniques T1078.002, T1059.001, and T1071.001. ' +
    'Risk assessment: HIGH. Recommend reviewing the correlated timeline in the case view.'
  );
}

const CONTEXT = {
  caseId: 'CS-2187',
  alertCount: 7,
  iocsFound: 3,
  riskLevel: 'High',
};

interface Props {
  /** Optional live run ID. When provided the Close button calls the real API. */
  runId?: string;
}

export default function InvestigationChat({ runId }: Props) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'sys-0',
      role: 'system',
      content: 'Investigation session started. Ask questions or use quick actions below.',
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [isClosed, setIsClosed] = useState(false);
  const [isClosing, setIsClosing] = useState(false);
  const [summary, setSummary] = useState<SummaryArtifact | null>(null);
  const [showSummary, setShowSummary] = useState(false);
  const [analystNote, setAnalystNote] = useState('');
  const [showNoteInput, setShowNoteInput] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length, isTyping]);

  const sendMessage = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isTyping || isClosed) return;

    const userMsg: ChatMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: trimmed,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsTyping(true);

    setTimeout(() => {
      const assistantMsg: ChatMessage = {
        id: `a-${Date.now()}`,
        role: 'assistant',
        content: getMockResponse(trimmed),
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
      setIsTyping(false);
    }, 500);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const handleCloseInvestigation = useCallback(async () => {
    setIsClosing(true);
    try {
      let artifactId: string;
      let summaryMarkdown: string;

      if (runId) {
        const res = await fetch(`/api/v1/investigations/${runId}/close`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ analyst_note: analystNote || null }),
        });
        if (!res.ok) {
          throw new Error(`Close failed: ${res.status} ${await res.text()}`);
        }
        const data = await res.json();
        artifactId = data.artifact_id;
        summaryMarkdown = data.summary_markdown;
      } else {
        // Offline / demo mode — build a local summary from message history
        artifactId = `demo-${Date.now()}`;
        const msgLines = messages
          .filter((m) => m.role !== 'system')
          .slice(-10)
          .map((m) => `- [${m.role.toUpperCase()}] ${m.content.slice(0, 120)}`)
          .join('\n');
        summaryMarkdown =
          `# Investigation Summary — ${CONTEXT.caseId}\n\n` +
          `**Status:** closed  \n**Case ID:** ${CONTEXT.caseId}  \n**Alerts:** ${CONTEXT.alertCount}  \n**IOCs:** ${CONTEXT.iocsFound}  \n**Risk:** ${CONTEXT.riskLevel}  \n\n` +
          `## Conversation (last 10 turns)\n\n${msgLines || '_No messages._'}\n\n` +
          (analystNote ? `## Analyst Note\n\n${analystNote}\n\n` : '') +
          `---\n*Generated by AiSOC — beenu@cyble.com*`;
      }

      setSummary({
        artifactId,
        summaryMarkdown,
        closedAt: new Date().toLocaleString(),
      });
      setIsClosed(true);
      setShowSummary(true);
      setShowNoteInput(false);

      const closedMsg: ChatMessage = {
        id: `sys-close-${Date.now()}`,
        role: 'system',
        content: '✓ Investigation closed. Summary generated and stored as an artifact.',
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, closedMsg]);
    } catch (err) {
      console.error('[InvestigationChat] close error:', err);
      const errMsg: ChatMessage = {
        id: `sys-err-${Date.now()}`,
        role: 'system',
        content: `Failed to close investigation: ${String(err)}`,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsClosing(false);
    }
  }, [runId, messages, analystNote]);

  const handleDownloadPdf = useCallback(async () => {
    if (!summary) return;
    setPdfLoading(true);

    try {
      if (runId) {
        const res = await fetch(`/api/v1/investigations/${runId}/summary.pdf`);
        if (!res.ok) throw new Error(`PDF fetch failed: ${res.status}`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `investigation-${runId}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        // Client-side plain-text fallback when no backend is available
        const blob = new Blob([summary.summaryMarkdown], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `investigation-${CONTEXT.caseId}.md`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('[InvestigationChat] PDF download error:', err);
    } finally {
      setPdfLoading(false);
    }
  }, [runId, summary]);

  return (
    <div className="flex h-[calc(100vh-7rem)] gap-4">
      {/* Main chat area */}
      <div className="flex flex-1 flex-col rounded-xl border border-slate-800/80 bg-slate-900/40">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800/80 px-4 py-3">
          <div>
            <h1 className="text-base font-semibold text-white">Investigation Chat</h1>
            <p className="text-xs text-slate-400">
              AI-assisted threat investigation — ask about alerts, IOCs, or cases
            </p>
          </div>

          {/* Close / Status controls */}
          <div className="flex shrink-0 items-center gap-2">
            {isClosed ? (
              <>
                <span className="rounded-full bg-slate-700/60 px-2.5 py-1 text-xs font-medium text-slate-400">
                  Closed
                </span>
                <button
                  onClick={() => setShowSummary((s) => !s)}
                  className="rounded-lg border border-slate-700/70 bg-slate-800/50 px-3 py-1.5 text-xs text-slate-300 hover:border-blue-500/40 hover:text-white"
                >
                  {showSummary ? 'Hide Summary' : 'View Summary'}
                </button>
                {summary && (
                  <button
                    onClick={handleDownloadPdf}
                    disabled={pdfLoading}
                    className="rounded-lg bg-blue-700/80 px-3 py-1.5 text-xs font-semibold text-white hover:bg-blue-600 disabled:opacity-50"
                  >
                    {pdfLoading ? 'Exporting…' : '↓ PDF'}
                  </button>
                )}
              </>
            ) : (
              <>
                {showNoteInput ? (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={analystNote}
                      onChange={(e) => setAnalystNote(e.target.value)}
                      placeholder="Optional analyst note…"
                      className="rounded-lg border border-slate-700/70 bg-slate-950/50 px-2 py-1.5 text-xs text-slate-200 placeholder-slate-500 outline-none focus:border-blue-500/50"
                    />
                    <button
                      onClick={handleCloseInvestigation}
                      disabled={isClosing}
                      className="rounded-lg bg-red-700/80 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-600 disabled:opacity-60"
                    >
                      {isClosing ? 'Closing…' : 'Confirm Close'}
                    </button>
                    <button
                      onClick={() => setShowNoteInput(false)}
                      className="rounded-lg border border-slate-700/70 px-2.5 py-1.5 text-xs text-slate-400 hover:text-white"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setShowNoteInput(true)}
                    disabled={isTyping}
                    className="rounded-lg border border-red-800/60 bg-red-950/30 px-3 py-1.5 text-xs font-semibold text-red-400 transition-colors hover:border-red-600/70 hover:bg-red-900/40 hover:text-red-300 disabled:opacity-50"
                  >
                    Close Investigation
                  </button>
                )}
              </>
            )}
          </div>
        </div>

        {/* Summary panel (shown when closed) */}
        {showSummary && summary && (
          <div className="border-b border-slate-800/80 bg-slate-950/60 px-4 py-4">
            <div className="mx-auto max-w-3xl">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">Investigation Summary</h3>
                <span className="text-[11px] text-slate-500">Closed {summary.closedAt}</span>
              </div>
              <pre className="max-h-64 overflow-y-auto whitespace-pre-wrap rounded-lg border border-slate-800/60 bg-slate-900/80 p-3 text-xs text-slate-300">
                {summary.summaryMarkdown}
              </pre>
              <p className="mt-1.5 text-[11px] text-slate-500">
                Artifact ID: <code className="text-slate-400">{summary.artifactId}</code>
              </p>
            </div>
          </div>
        )}

        {/* Messages */}
        <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto p-4">
          <ul className="mx-auto max-w-3xl space-y-3">
            {messages.map((m) => {
              if (m.role === 'system') {
                return (
                  <li key={m.id} className="flex justify-center">
                    <span className="rounded-full bg-slate-800/50 px-3 py-1 text-xs text-slate-500">
                      {m.content}
                    </span>
                  </li>
                );
              }
              const isUser = m.role === 'user';
              return (
                <li key={m.id} className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                  <div
                    className={`max-w-[80%] whitespace-pre-wrap rounded-2xl px-4 py-3 text-sm ${
                      isUser
                        ? 'bg-blue-600/20 text-white ring-1 ring-blue-500/30'
                        : 'bg-slate-800/70 text-slate-100 ring-1 ring-slate-700/60'
                    }`}
                  >
                    {m.content}
                  </div>
                </li>
              );
            })}
            {isTyping && (
              <li className="flex justify-start">
                <div className="rounded-2xl bg-slate-800/70 px-4 py-3 ring-1 ring-slate-700/60">
                  <span className="inline-flex items-center gap-1 text-slate-400">
                    <span className="animate-pulse">●</span>
                    <span className="animate-pulse" style={{ animationDelay: '0.2s' }}>●</span>
                    <span className="animate-pulse" style={{ animationDelay: '0.4s' }}>●</span>
                  </span>
                </div>
              </li>
            )}
          </ul>
        </div>

        {/* Quick actions + input */}
        <div className="border-t border-slate-800/80 p-3">
          {!isClosed && (
            <div className="mx-auto flex max-w-3xl flex-wrap gap-2 pb-2">
              {QUICK_ACTIONS.map((action) => (
                <button
                  key={action}
                  onClick={() => sendMessage(action)}
                  disabled={isTyping}
                  className="rounded-full border border-slate-700/70 bg-slate-800/50 px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-blue-500/40 hover:bg-slate-700/60 hover:text-white disabled:opacity-50"
                >
                  {action}
                </button>
              ))}
            </div>
          )}

          {isClosed ? (
            <p className="mx-auto max-w-3xl text-center text-xs text-slate-500">
              This investigation is closed. Open a new session to continue.
            </p>
          ) : (
            <div className="mx-auto flex max-w-3xl items-end gap-2 rounded-xl border border-slate-700/70 bg-slate-950/40 p-2 focus-within:border-blue-500/50">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={onKeyDown}
                rows={1}
                placeholder="Ask about an alert, IOC, or investigation…"
                className="flex-1 resize-none bg-transparent px-2 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none"
              />
              <button
                onClick={() => sendMessage(input)}
                disabled={!input.trim() || isTyping}
                className={`flex-none rounded-lg px-3 py-2 text-sm font-semibold transition-colors ${
                  input.trim() && !isTyping
                    ? 'bg-blue-600 text-white hover:bg-blue-500'
                    : 'bg-slate-800 text-slate-500'
                }`}
              >
                Send
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Context panel */}
      <aside className="hidden w-64 flex-col gap-4 rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 lg:flex">
        <h2 className="text-sm font-semibold text-white">Investigation Context</h2>

        <div className="space-y-3">
          <div className="rounded-lg border border-slate-800/80 bg-slate-800/30 p-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
              Case ID
            </p>
            <p className="mt-1 font-mono text-sm text-white">{CONTEXT.caseId}</p>
          </div>

          <div className="rounded-lg border border-slate-800/80 bg-slate-800/30 p-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
              Alert Count
            </p>
            <p className="mt-1 text-2xl font-bold text-white">{CONTEXT.alertCount}</p>
          </div>

          <div className="rounded-lg border border-slate-800/80 bg-slate-800/30 p-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
              IOCs Found
            </p>
            <p className="mt-1 text-2xl font-bold text-amber-400">{CONTEXT.iocsFound}</p>
          </div>

          <div className="rounded-lg border border-slate-800/80 bg-slate-800/30 p-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
              Risk Level
            </p>
            <p className="mt-1 text-lg font-bold text-red-400">{CONTEXT.riskLevel}</p>
          </div>

          {/* Status badge */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-800/30 p-3">
            <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
              Status
            </p>
            <p className={`mt-1 text-sm font-semibold ${isClosed ? 'text-slate-400' : 'text-emerald-400'}`}>
              {isClosed ? '⬛ Closed' : '🟢 Active'}
            </p>
          </div>
        </div>

        <div className="mt-auto rounded-lg border border-slate-800/80 bg-slate-800/30 p-3">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Session
          </p>
          <p className="mt-1 text-xs text-slate-400">
            {messages.filter((m) => m.role === 'user').length} messages sent
          </p>
          <p className="text-xs text-slate-400">
            {messages.filter((m) => m.role === 'assistant').length} AI responses
          </p>
        </div>
      </aside>
    </div>
  );
}
