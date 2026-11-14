import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import htm from 'htm';

const html = htm.bind(React.createElement);
const API = window.AISOC_API_URL || 'http://localhost:8478';

// ────────────────────────────────────────────────────────────────────────
// Hooks
// ────────────────────────────────────────────────────────────────────────
function useFetch(path, deps = []) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch(`${API}${path}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setData(d);
      setErr(null);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => { reload(); }, deps);
  return { data, err, loading, reload };
}

function useEventStream() {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let ws;
    let stopped = false;
    const connect = () => {
      const url = API.replace(/^http/, 'ws') + '/ws/events';
      ws = new WebSocket(url);
      ws.onopen = () => setConnected(true);
      ws.onmessage = e => {
        try {
          const ev = JSON.parse(e.data);
          setEvents(prev => [...prev.slice(-99), ev]);
        } catch {}
      };
      ws.onclose = () => {
        setConnected(false);
        if (!stopped) setTimeout(connect, 1500);
      };
      ws.onerror = () => ws.close();
    };
    connect();
    return () => { stopped = true; ws && ws.close(); };
  }, []);

  return { events, connected };
}

// ────────────────────────────────────────────────────────────────────────
// Components
// ────────────────────────────────────────────────────────────────────────
function Sidebar({ page, setPage, stats }) {
  const items = [
    { id: 'queue',    icon: '🛡',   label: 'Triage Queue' },
    { id: 'hunter',   icon: '🎯',   label: 'Hunter' },
    { id: 'tools',    icon: '🔌',   label: 'Tools & Integrations' },
    { id: 'manager',  icon: '📊',   label: 'Manager Dashboard' },
  ];
  return html`
    <aside class="w-64 min-w-64 bg-surface border-r border-border flex flex-col">
      <div class="px-5 py-5 border-b border-border">
        <div class="flex items-center gap-3">
          <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-base">🛡</div>
          <div>
            <div class="text-[15px] font-bold text-slate-100 tracking-tight">Cyble AiSOC</div>
            <div class="text-[10.5px] text-slate-500 uppercase tracking-widest">Analyst Console</div>
          </div>
        </div>
        <div class="mt-3 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/30 text-[10.5px] text-blue-400">
          <span class="w-1.5 h-1.5 rounded-full bg-blue-400 pulse-dot"></span>
          Demo · Mock LLM
        </div>
      </div>

      <nav class="flex-1 p-3">
        ${items.map(it => html`
          <button
            key=${it.id}
            onClick=${() => setPage(it.id)}
            class=${"w-full text-left flex items-center gap-2.5 px-3 py-2 rounded-lg text-[13.5px] mb-0.5 transition-all " +
              (page === it.id
                ? "bg-blue-500/12 border border-blue-500/30 text-blue-400 font-medium"
                : "border border-transparent text-slate-400 hover:bg-surface2 hover:text-slate-200")}
          >
            <span class="text-base w-5 text-center">${it.icon}</span>
            ${it.label}
          </button>
        `)}
      </nav>

      ${stats ? html`
        <div class="px-3 py-3 border-t border-border text-[11px] text-slate-500 space-y-1.5">
          <div class="flex justify-between"><span>Cases</span><span class="text-slate-300">${stats.total_cases}</span></div>
          <div class="flex justify-between"><span>Auto-resolved</span><span class="text-emerald-400">${(stats.auto_resolution_rate * 100).toFixed(0)}%</span></div>
          <div class="flex justify-between"><span>Tools</span><span class="text-slate-300">${stats.tools_registered}</span></div>
        </div>
      ` : null}
    </aside>
  `;
}

function TopBar({ connected, latestEvent, page }) {
  const titles = {
    queue: 'Triage Queue',
    hunter: 'Threat Hunter Workspace',
    tools: 'Tool & Integration Registry',
    manager: 'SOC Manager Dashboard',
  };
  return html`
    <header class="h-14 border-b border-border bg-surface flex items-center px-6 gap-4">
      <div class="text-[14px] font-semibold text-slate-100">${titles[page] || ''}</div>
      <div class="flex-1"></div>
      <div class="flex items-center gap-2 text-[12px]">
        <span class=${"w-1.5 h-1.5 rounded-full " + (connected ? 'bg-emerald-400 pulse-dot' : 'bg-slate-600')}></span>
        <span class="text-slate-500">${connected ? 'Live' : 'Disconnected'}</span>
      </div>
      ${latestEvent ? html`
        <div class="font-mono text-[11px] text-slate-500 max-w-md truncate">
          ${latestEvent.type}: ${latestEvent.msg || latestEvent.summary || latestEvent.agent || ''}
        </div>
      ` : null}
    </header>
  `;
}

// ────────────────────────────────────────────────────────────────────────
// QUEUE PAGE
// ────────────────────────────────────────────────────────────────────────
function QueuePage({ onOpen }) {
  const { data: cases, loading, reload } = useFetch('/cases', []);
  const [filter, setFilter] = useState('all');
  const [running, setRunning] = useState(new Set());

  // Auto-refresh while a case is running
  useEffect(() => {
    if (running.size === 0) return;
    const t = setInterval(reload, 1500);
    return () => clearInterval(t);
  }, [running, reload]);

  const filtered = useMemo(() => {
    if (!cases) return [];
    if (filter === 'all') return cases;
    if (filter === 'open') return cases.filter(c => !c.status.startsWith('closed_'));
    if (filter === 'closed') return cases.filter(c => c.status.startsWith('closed_'));
    return cases.filter(c => c.severity === filter);
  }, [cases, filter]);

  const runAll = async () => {
    const open = (cases || []).filter(c => c.status === 'new');
    if (!open.length) return;
    if (!confirm(`Run agent triage on ${open.length} new case(s)?`)) return;
    const ids = new Set(open.map(c => c.id));
    setRunning(ids);
    for (const c of open) {
      try { await fetch(`${API}/cases/${c.id}/rerun`, { method: 'POST' }); } catch {}
    }
    setTimeout(() => setRunning(new Set()), 6000);
  };

  const runOne = async (caseId) => {
    setRunning(prev => new Set(prev).add(caseId));
    try { await fetch(`${API}/cases/${caseId}/rerun`, { method: 'POST' }); } catch {}
    setTimeout(() => setRunning(prev => { const n = new Set(prev); n.delete(caseId); return n; }), 5000);
  };

  return html`
    <div class="flex-1 overflow-auto p-6">
      <div class="flex items-center gap-3 mb-5">
        <div class="flex bg-surface2 rounded-lg p-1 text-[12.5px]">
          ${['all', 'open', 'closed', 'critical', 'high', 'medium'].map(f => html`
            <button
              key=${f}
              onClick=${() => setFilter(f)}
              class=${"px-3 py-1 rounded-md " + (filter === f ? 'bg-blue-500/20 text-blue-400' : 'text-slate-400 hover:text-slate-200')}
            >${f}</button>
          `)}
        </div>
        <div class="flex-1"></div>
        <button
          onClick=${runAll}
          class="px-3.5 py-1.5 bg-blue-500 hover:bg-blue-600 text-white text-[12.5px] rounded-lg font-medium"
        >▶ Run agents on new cases</button>
        <button
          onClick=${reload}
          class="px-3 py-1.5 bg-surface2 hover:bg-border text-slate-300 text-[12.5px] rounded-lg"
        >↻ Refresh</button>
      </div>

      <div class="bg-surface border border-border rounded-xl overflow-hidden">
        <table class="w-full text-[13px]">
          <thead>
            <tr class="bg-surface2 text-[10.5px] uppercase tracking-widest text-slate-500">
              <th class="text-left py-2.5 px-4 font-medium">Sev</th>
              <th class="text-left py-2.5 px-2 font-medium">Title</th>
              <th class="text-left py-2.5 px-2 font-medium">Status</th>
              <th class="text-left py-2.5 px-2 font-medium">Verdict</th>
              <th class="text-left py-2.5 px-2 font-medium">Conf</th>
              <th class="text-left py-2.5 px-2 font-medium">MITRE</th>
              <th class="text-right py-2.5 px-4 font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            ${filtered.map(c => html`
              <tr key=${c.id} class="border-t border-border hover:bg-surface2/50 transition-colors cursor-pointer fade-in" onClick=${() => onOpen(c.id)}>
                <td class="py-3 px-4">
                  <span class=${"pill sev-" + c.severity}>${c.severity}</span>
                </td>
                <td class="py-3 px-2 text-slate-100">
                  <div class="font-medium">${c.title}</div>
                  <div class="text-[11.5px] text-slate-500 mt-0.5">#${c.id} · ${new Date(c.created_at).toLocaleTimeString()}</div>
                </td>
                <td class="py-3 px-2 text-slate-400 text-[12px]">${prettyStatus(c.status)}</td>
                <td class=${"py-3 px-2 text-[12px] verdict-" + c.verdict}>${c.verdict.replace('_', ' ')}</td>
                <td class="py-3 px-2 text-slate-400 text-[12px] font-mono">${(c.confidence * 100).toFixed(0)}%</td>
                <td class="py-3 px-2 text-[11px] font-mono text-slate-500">
                  ${(c.mitre_techniques || []).slice(0, 2).join(', ') || '—'}
                </td>
                <td class="py-3 px-4 text-right">
                  ${c.status === 'new' ? html`
                    <button
                      onClick=${e => { e.stopPropagation(); runOne(c.id); }}
                      disabled=${running.has(c.id)}
                      class="px-2.5 py-1 bg-blue-500/15 border border-blue-500/30 text-blue-400 text-[11.5px] rounded hover:bg-blue-500/25 disabled:opacity-50"
                    >${running.has(c.id) ? '⏳ Running...' : '▶ Run'}</button>
                  ` : html`<span class="text-[11px] text-slate-600">—</span>`}
                </td>
              </tr>
            `)}
            ${filtered.length === 0 ? html`
              <tr><td colSpan="7" class="py-12 text-center text-slate-500">${loading ? 'Loading...' : 'No cases match this filter.'}</td></tr>
            ` : null}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function prettyStatus(s) {
  return s.replace('_', ' ').replace('closed ', 'closed: ');
}

// ────────────────────────────────────────────────────────────────────────
// CASE DETAIL
// ────────────────────────────────────────────────────────────────────────
function CaseDetail({ caseId, onBack }) {
  const { data: c, loading, reload } = useFetch(`/cases/${caseId}`, [caseId]);

  // Refresh every 1.5s if case is still running
  useEffect(() => {
    if (!c) return;
    if (['new', 'triaging', 'investigating', 'responding'].includes(c.status)) {
      const t = setInterval(reload, 1500);
      return () => clearInterval(t);
    }
  }, [c, reload]);

  const rerun = async () => {
    await fetch(`${API}/cases/${caseId}/rerun`, { method: 'POST' });
    setTimeout(reload, 500);
  };

  if (loading || !c) {
    return html`<div class="flex-1 flex items-center justify-center text-slate-500">Loading...</div>`;
  }

  // Group traces by agent
  const tracesByAgent = (c.traces || []).reduce((acc, t) => {
    (acc[t.agent] = acc[t.agent] || []).push(t);
    return acc;
  }, {});

  return html`
    <div class="flex-1 flex overflow-hidden">

      <!-- LEFT: case overview -->
      <div class="flex-1 overflow-auto p-6">
        <button
          onClick=${onBack}
          class="text-[12.5px] text-slate-400 hover:text-slate-200 mb-4 inline-flex items-center gap-1.5"
        >← Back to queue</button>

        <div class="flex items-start gap-3 mb-1">
          <span class=${"pill sev-" + c.severity + " mt-1"}>${c.severity}</span>
          <h1 class="text-[20px] font-bold text-slate-100 leading-tight">${c.title}</h1>
        </div>
        <div class="flex items-center gap-3 text-[11.5px] text-slate-500 ml-1 mb-5">
          <span>Case #${c.id}</span>
          <span>·</span>
          <span class=${"verdict-" + c.verdict}>${c.verdict.replace('_', ' ')}</span>
          <span>·</span>
          <span>Confidence: <span class="text-slate-300 font-mono">${(c.confidence * 100).toFixed(0)}%</span></span>
          <span>·</span>
          <span>Status: <span class="text-slate-300">${prettyStatus(c.status)}</span></span>
          <span class="flex-1"></span>
          <button onClick=${rerun} class="px-2.5 py-1 bg-blue-500/15 border border-blue-500/30 text-blue-400 text-[11.5px] rounded hover:bg-blue-500/25">↻ Rerun agents</button>
        </div>

        ${c.narrative ? html`
          <section class="mb-5 p-4 bg-blue-500/5 border border-blue-500/20 rounded-xl">
            <div class="text-[10.5px] uppercase tracking-widest text-blue-400 mb-2 font-semibold">Auto-narrative · Reporter Agent</div>
            <div class="prose-narrative text-[13.5px] text-slate-200 whitespace-pre-wrap">${c.narrative}</div>
          </section>
        ` : null}

        ${(c.alerts || []).map(a => html`
          <section key=${a.id} class="mb-4 p-4 bg-surface border border-border rounded-xl">
            <div class="text-[10.5px] uppercase tracking-widest text-slate-500 mb-2 font-semibold">Source alert · ${a.source}</div>
            <div class="text-[13.5px] text-slate-200">${a.title}</div>
            <div class="text-[12.5px] text-slate-400 mt-1">${a.description}</div>
            <div class="grid grid-cols-2 md:grid-cols-3 gap-3 mt-4 text-[12px]">
              ${a.src_user ? html`<${KV} k="User" v=${a.src_user} />` : null}
              ${a.src_host ? html`<${KV} k="Host" v=${a.src_host} />` : null}
              ${a.src_ip ? html`<${KV} k="Src IP" v=${a.src_ip} mono />` : null}
              ${a.dst_ip ? html`<${KV} k="Dst" v=${a.dst_ip} mono />` : null}
              ${a.process_name ? html`<${KV} k="Process" v=${a.process_name} mono />` : null}
              ${a.file_hash ? html`<${KV} k="SHA256" v=${a.file_hash.slice(0, 16) + '...'} mono />` : null}
              ${a.detection_rule ? html`<${KV} k="Rule" v=${a.detection_rule} mono />` : null}
              ${(a.mitre_techniques || []).length ? html`<${KV} k="MITRE" v=${a.mitre_techniques.join(', ')} mono />` : null}
            </div>
          </section>
        `)}

        ${(c.iocs || []).length ? html`
          <section class="mb-4 p-4 bg-surface border border-border rounded-xl">
            <div class="text-[10.5px] uppercase tracking-widest text-slate-500 mb-2 font-semibold">Confirmed IOCs</div>
            <div class="flex flex-wrap gap-2">
              ${c.iocs.map(ioc => html`
                <span key=${ioc} class="font-mono text-[12px] px-2.5 py-1 bg-red-500/10 border border-red-500/25 text-red-300 rounded">${ioc}</span>
              `)}
            </div>
          </section>
        ` : null}

        ${(c.response_actions || []).length ? html`
          <section class="mb-4 p-4 bg-surface border border-border rounded-xl">
            <div class="text-[10.5px] uppercase tracking-widest text-slate-500 mb-2 font-semibold">Response actions executed</div>
            <ul class="text-[13px] text-slate-300 space-y-1.5">
              ${c.response_actions.map((a, i) => html`
                <li key=${i} class="flex items-center gap-2">
                  <span class="text-emerald-400">✓</span>
                  <span class="font-mono text-[12px] text-blue-300">${a.action}</span>
                  <span class="text-slate-500 text-[12px]">${JSON.stringify(Object.fromEntries(Object.entries(a).filter(([k]) => k !== 'action' && k !== 'result'))).slice(1, -1) || ''}</span>
                </li>
              `)}
            </ul>
          </section>
        ` : null}
      </div>

      <!-- RIGHT: agent transparency panel -->
      <aside class="w-[480px] min-w-[480px] border-l border-border bg-surface overflow-auto">
        <div class="px-5 py-4 border-b border-border sticky top-0 bg-surface z-10">
          <div class="text-[11px] uppercase tracking-widest text-blue-400 font-semibold">🤖 Agent transparency · why did the agents do that?</div>
          <div class="text-[12px] text-slate-500 mt-1">${(c.traces || []).length} steps · ${(c.tool_calls || []).length} tool calls</div>
        </div>

        <div class="p-4 space-y-4">
          ${Object.entries(tracesByAgent).map(([agent, traces]) => html`
            <div key=${agent} class="bg-surface2 rounded-lg border border-border overflow-hidden">
              <div class=${"px-3 py-2 border-b border-border flex items-center gap-2 text-[12.5px] font-semibold agent-" + agent}>
                <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
                ${agent.toUpperCase()}
                <span class="text-slate-500 text-[11px] font-normal">${traces.length} step${traces.length > 1 ? 's' : ''}</span>
              </div>
              <div class="p-3 space-y-2">
                ${traces.map(t => html`<${TraceItem} key=${t.id} t=${t} toolCalls=${c.tool_calls || []} />`)}
              </div>
            </div>
          `)}
          ${(c.traces || []).length === 0 ? html`
            <div class="text-center text-slate-500 py-12 text-[13px]">No agent traces yet. Click "Rerun agents" to start.</div>
          ` : null}
        </div>
      </aside>
    </div>
  `;
}

function KV({ k, v, mono }) {
  return html`
    <div>
      <div class="text-[10.5px] uppercase tracking-widest text-slate-500">${k}</div>
      <div class=${"text-slate-200 " + (mono ? 'font-mono text-[11.5px]' : 'text-[12.5px]')}>${v}</div>
    </div>
  `;
}

function TraceItem({ t, toolCalls }) {
  const [open, setOpen] = useState(false);
  const stepIcon = {
    plan: '📋', think: '💭', tool_call: '🔧', decision: '⚡', handoff: '↪️',
    hitl: '🙋', error: '❌',
  }[t.step] || '·';
  const linkedTool = toolCalls.find(tc => tc.trace_id === t.id);

  return html`
    <div class="text-[12.5px]">
      <div
        class="flex gap-2 cursor-pointer hover:text-slate-100"
        onClick=${() => setOpen(!open)}
      >
        <span class="text-[14px] leading-snug">${stepIcon}</span>
        <div class="flex-1">
          <div class="text-slate-300 leading-snug">${t.summary}</div>
          ${linkedTool ? html`
            <div class="mt-1 flex items-center gap-1.5">
              <span class=${"pill risk-" + linkedTool.risk_class}>${linkedTool.risk_class}</span>
              <span class="text-[11px] text-slate-500 font-mono">${linkedTool.integration}</span>
              <span class="text-[10px] text-slate-600">${linkedTool.duration_ms}ms</span>
              ${linkedTool.hitl_required ? html`<span class="text-[10px] text-amber-400">⚠ HITL</span>` : null}
            </div>
          ` : null}
        </div>
        ${(t.detail && Object.keys(t.detail).length > 0) || linkedTool ? html`
          <span class="text-[11px] text-slate-600">${open ? '▼' : '▶'}</span>
        ` : null}
      </div>
      ${open ? html`
        <div class="ml-6 mt-2 p-2 bg-bg border border-border rounded text-[11px] font-mono text-slate-400 max-h-64 overflow-auto">
          ${linkedTool ? html`
            <div class="mb-2">
              <div class="text-[10px] uppercase text-slate-500">Result</div>
              <pre class="whitespace-pre-wrap break-all">${JSON.stringify(linkedTool.result, null, 2)}</pre>
            </div>
          ` : null}
          ${t.detail && Object.keys(t.detail).length > 0 ? html`
            <div>
              <div class="text-[10px] uppercase text-slate-500">Detail</div>
              <pre class="whitespace-pre-wrap break-all">${JSON.stringify(t.detail, null, 2)}</pre>
            </div>
          ` : null}
        </div>
      ` : null}
    </div>
  `;
}

// ────────────────────────────────────────────────────────────────────────
// HUNTER
// ────────────────────────────────────────────────────────────────────────
function HunterPage() {
  const [hyp, setHyp] = useState('');
  const [results, setResults] = useState([]);
  const [running, setRunning] = useState(false);

  const presets = [
    'Look for credential leaks of cyble.com on dark-web in last 30 days',
    'Find externally exposed services with known CVEs',
    'Hunt for Cobalt Strike beacon patterns in last 4 hours',
    'Show me lateral-movement chains involving WIN-FIN-0044',
  ];

  const run = async (text) => {
    const hypothesis = text || hyp;
    if (!hypothesis.trim()) return;
    setRunning(true);
    try {
      const r = await fetch(`${API}/hunts`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hypothesis }),
      });
      const d = await r.json();
      // Pull case detail to get traces
      const detail = await fetch(`${API}/cases/${d.case_id}`).then(r => r.json());
      setResults(prev => [{ hypothesis, detail }, ...prev]);
    } finally {
      setRunning(false);
    }
  };

  return html`
    <div class="flex-1 overflow-auto p-6 max-w-5xl">
      <div class="mb-5">
        <h2 class="text-[18px] font-bold text-slate-100">Hypothesis-driven hunting</h2>
        <p class="text-[13px] text-slate-500 mt-1">Pose a question. The Hunter agent picks the right tools, runs queries, summarizes findings, and suggests follow-ups.</p>
      </div>

      <div class="bg-surface border border-border rounded-xl p-4 mb-5">
        <textarea
          value=${hyp}
          onChange=${e => setHyp(e.target.value)}
          placeholder="What are you trying to find?"
          rows=${3}
          class="w-full bg-bg border border-border rounded-lg px-3 py-2.5 text-[13.5px] text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-500/60"
        ></textarea>
        <div class="flex items-center gap-2 mt-3">
          <button
            onClick=${() => run()}
            disabled=${running || !hyp.trim()}
            class="px-4 py-1.5 bg-blue-500 hover:bg-blue-600 text-white text-[12.5px] rounded-lg font-medium disabled:opacity-40"
          >${running ? '⏳ Hunting...' : '🎯 Run hunt'}</button>
          <span class="text-[11.5px] text-slate-500 ml-2">or try a preset:</span>
        </div>
        <div class="flex flex-wrap gap-1.5 mt-3">
          ${presets.map(p => html`
            <button
              key=${p}
              onClick=${() => { setHyp(p); run(p); }}
              class="text-[11.5px] text-slate-400 px-2.5 py-1 bg-surface2 hover:bg-border rounded-md border border-border"
            >${p}</button>
          `)}
        </div>
      </div>

      <div class="space-y-4">
        ${results.map((r, i) => html`
          <div key=${i} class="bg-surface border border-border rounded-xl p-4 fade-in">
            <div class="text-[10.5px] uppercase tracking-widest text-pink-400 font-semibold mb-1">Hypothesis</div>
            <div class="text-[13.5px] text-slate-200 mb-3">${r.hypothesis}</div>
            <div class="text-[10.5px] uppercase tracking-widest text-slate-500 font-semibold mb-2">Hunter trace</div>
            <div class="space-y-1.5">
              ${(r.detail.traces || []).map(t => html`
                <div key=${t.id} class="flex items-start gap-2 text-[12.5px]">
                  <span class="font-mono text-[10.5px] text-slate-500 mt-0.5">${t.step}</span>
                  <span class="text-slate-300">${t.summary}</span>
                </div>
              `)}
            </div>
            ${(r.detail.tool_calls || []).length ? html`
              <div class="mt-3 flex flex-wrap gap-1.5">
                ${r.detail.tool_calls.map((tc, j) => html`
                  <span key=${j} class="font-mono text-[11px] px-2 py-0.5 rounded bg-surface2 text-slate-400">${tc.tool_name}</span>
                `)}
              </div>
            ` : null}
          </div>
        `)}
        ${results.length === 0 ? html`
          <div class="text-center text-slate-500 py-12 text-[13px]">No hunts yet — pose a hypothesis or pick a preset.</div>
        ` : null}
      </div>
    </div>
  `;
}

// ────────────────────────────────────────────────────────────────────────
// TOOLS
// ────────────────────────────────────────────────────────────────────────
function ToolsPage() {
  const { data: tools, loading } = useFetch('/tools', []);
  const [filter, setFilter] = useState('all');
  if (loading) return html`<div class="flex-1 p-6 text-slate-500">Loading...</div>`;

  const filtered = (tools || []).filter(t => {
    if (filter === 'all') return true;
    if (filter === 'cyble') return t.cyble_native;
    return t.risk_class === filter;
  });

  // Group by integration
  const byInteg = filtered.reduce((acc, t) => {
    (acc[t.integration] = acc[t.integration] || []).push(t);
    return acc;
  }, {});

  return html`
    <div class="flex-1 overflow-auto p-6">
      <div class="mb-5 flex items-center gap-3">
        <h2 class="text-[18px] font-bold text-slate-100">${(tools || []).length} tools registered</h2>
        <span class="text-[12px] text-emerald-400">${(tools || []).filter(t => t.cyble_native).length} Cyble-native</span>
        <div class="flex-1"></div>
        <div class="flex bg-surface2 rounded-lg p-1 text-[12px]">
          ${['all', 'cyble', 'READ', 'WRITE-REVERSIBLE', 'WRITE-SIGNIFICANT', 'DESTRUCTIVE'].map(f => html`
            <button key=${f} onClick=${() => setFilter(f)}
              class=${"px-2.5 py-1 rounded-md " + (filter === f ? 'bg-blue-500/20 text-blue-400' : 'text-slate-400 hover:text-slate-200')}
            >${f}</button>
          `)}
        </div>
      </div>

      <div class="space-y-4">
        ${Object.entries(byInteg).map(([integ, ts]) => html`
          <div key=${integ} class="bg-surface border border-border rounded-xl overflow-hidden">
            <div class="px-4 py-2 bg-surface2 border-b border-border flex items-center gap-2">
              <span class="font-mono text-[12.5px] font-semibold text-slate-200">${integ}</span>
              ${ts[0].cyble_native ? html`<span class="text-[10px] px-1.5 py-0.5 bg-purple-500/20 text-purple-300 rounded font-medium">CYBLE NATIVE</span>` : null}
              <span class="text-[11px] text-slate-500">${ts.length} tool${ts.length > 1 ? 's' : ''}</span>
            </div>
            <div class="divide-y divide-border">
              ${ts.map(t => html`
                <div key=${t.name} class="px-4 py-3 flex items-start gap-3">
                  <span class=${"pill risk-" + t.risk_class + " mt-0.5"}>${t.risk_class}</span>
                  <div class="flex-1">
                    <div class="font-mono text-[13px] text-slate-100">${t.name}</div>
                    <div class="text-[12.5px] text-slate-400 mt-0.5">${t.description}</div>
                  </div>
                </div>
              `)}
            </div>
          </div>
        `)}
      </div>
    </div>
  `;
}

// ────────────────────────────────────────────────────────────────────────
// MANAGER
// ────────────────────────────────────────────────────────────────────────
function ManagerPage({ stats, events }) {
  if (!stats) return html`<div class="flex-1 p-6 text-slate-500">Loading...</div>`;

  return html`
    <div class="flex-1 overflow-auto p-6">
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <${StatCard} label="Total cases" value=${stats.total_cases} />
        <${StatCard} label="Auto-resolution rate" value=${(stats.auto_resolution_rate * 100).toFixed(0) + '%'} accent />
        <${StatCard} label="Avg MTTR" value=${stats.avg_mttr_seconds ? formatDur(stats.avg_mttr_seconds) : '—'} />
        <${StatCard} label="Tools wired" value=${stats.tools_registered} />
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <${BarBreakdown} title="By severity" data=${stats.by_severity} colorBy="severity" />
        <${BarBreakdown} title="By status" data=${stats.by_status} />
      </div>

      <div class="bg-surface border border-border rounded-xl p-4">
        <div class="text-[10.5px] uppercase tracking-widest text-blue-400 font-semibold mb-3">Live agent activity feed</div>
        <div class="space-y-1 font-mono text-[11.5px] max-h-72 overflow-auto">
          ${[...(events || [])].reverse().slice(0, 30).map((ev, i) => html`
            <div key=${i} class="text-slate-400 flex gap-3">
              <span class="text-slate-600">${(ev.ts || '').slice(11, 19)}</span>
              <span class=${"agent-" + (ev.agent || 'planner')}>${(ev.agent || 'sys').padEnd(13)}</span>
              <span>${ev.summary || ev.msg || ev.type}</span>
            </div>
          `)}
          ${(events || []).length === 0 ? html`<div class="text-slate-600 italic">Waiting for activity... run a case to see live events here.</div>` : null}
        </div>
      </div>
    </div>
  `;
}

function StatCard({ label, value, accent }) {
  return html`
    <div class=${"bg-surface border rounded-xl p-4 " + (accent ? 'border-blue-500/30 glow' : 'border-border')}>
      <div class="text-[10.5px] uppercase tracking-widest text-slate-500">${label}</div>
      <div class="text-[26px] font-bold text-slate-100 mt-1 leading-none">${value}</div>
    </div>
  `;
}

function BarBreakdown({ title, data, colorBy }) {
  const entries = Object.entries(data || {});
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return html`
    <div class="bg-surface border border-border rounded-xl p-4">
      <div class="text-[10.5px] uppercase tracking-widest text-slate-500 mb-3">${title}</div>
      <div class="space-y-2">
        ${entries.map(([k, v]) => html`
          <div key=${k} class="flex items-center gap-3 text-[12.5px]">
            <span class=${"w-32 truncate " + (colorBy === 'severity' ? 'verdict-' : '') + (colorBy === 'severity' && k ? '' : 'text-slate-400')}>${k}</span>
            <div class="flex-1 h-2 bg-bg rounded overflow-hidden">
              <div class="h-full bg-blue-500/60" style=${{ width: (v / max * 100) + '%' }}></div>
            </div>
            <span class="font-mono text-slate-300 w-8 text-right">${v}</span>
          </div>
        `)}
      </div>
    </div>
  `;
}

function formatDur(s) {
  if (s < 60) return `${s.toFixed(1)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

// ────────────────────────────────────────────────────────────────────────
// ROOT
// ────────────────────────────────────────────────────────────────────────
function App() {
  const [page, setPage] = useState('queue');
  const [openCaseId, setOpenCaseId] = useState(null);
  const { data: stats } = useFetch('/stats', [page]);
  const { events, connected } = useEventStream();

  const latestEvent = events[events.length - 1];

  return html`
    <div class="flex h-screen w-screen overflow-hidden">
      <${Sidebar} page=${page} setPage=${(p) => { setPage(p); setOpenCaseId(null); }} stats=${stats} />
      <div class="flex-1 flex flex-col">
        <${TopBar} connected=${connected} latestEvent=${latestEvent} page=${page} />
        ${openCaseId
          ? html`<${CaseDetail} caseId=${openCaseId} onBack=${() => setOpenCaseId(null)} />`
          : page === 'queue'   ? html`<${QueuePage} onOpen=${setOpenCaseId} />`
          : page === 'hunter'  ? html`<${HunterPage} />`
          : page === 'tools'   ? html`<${ToolsPage} />`
          : page === 'manager' ? html`<${ManagerPage} stats=${stats} events=${events} />`
          : null}
      </div>
    </div>
  `;
}

const root = createRoot(document.getElementById('root'));
root.render(html`<${App} />`);
