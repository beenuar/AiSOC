'use client';

/**
 * Case workspace.
 *
 * The single screen an analyst lives on while working an incident:
 *   - Header with title, severity, status, assignee, timing, MITRE tags
 *   - Action bar: status transitions, assign, link alerts, run copilot
 *   - Three-pane layout
 *       Left:    summary + linked alerts + assets/IOCs
 *       Center:  timeline (audit + activity feed)
 *       Right:   tasks + notes
 *
 * Like the rest of the app, this gracefully falls back to demo data if the
 * backend hasn't been seeded.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import {
  casesApi,
  graphApi,
  realtimeApi,
  type AttackChainTimeline,
  type AttackChainWindow,
  type Case,
  type CaseAttackPath,
  type CaseSeverity,
  type CaseStatus,
  type CaseTask,
  type CaseTimelineEvent,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';
import { InvestigationLedger } from './InvestigationLedger';
import { ContextualActions } from '@/components/copilot/ContextualActions';

type WorkspaceTab =
  | 'overview'
  | 'investigation'
  | 'attack-path'
  | 'attack-chain'
  | 'ledger'
  | 'report';

const VALID_TABS: readonly WorkspaceTab[] = [
  'overview',
  'investigation',
  'attack-path',
  'attack-chain',
  'ledger',
  'report',
];

function isWorkspaceTab(value: string | null): value is WorkspaceTab {
  return value !== null && (VALID_TABS as readonly string[]).includes(value);
}

// ─── Demo case ────────────────────────────────────────────────────────────────

function buildDemoCase(id: string): Case {
  const now = new Date('2026-05-06T12:00:00Z').getTime();
  return {
    id,
    title: 'Suspected lateral movement from finance subnet',
    description:
      "Multiple high-severity alerts indicate an attacker pivoted from " +
      "WIN-FIN-DB01 to BACKUP-SRV-12 using compromised service account credentials. " +
      "Behavior consistent with T1021.002 (SMB/Windows Admin Shares).",
    status: 'in_progress',
    severity: 'critical',
    assignee: 'sasha.lin@example.com',
    alertIds: ['alert-9012', 'alert-9013', 'alert-9019', 'alert-9024'],
    alertCount: 4,
    tags: ['lateral-movement', 'credential-access', 'finance-subnet'],
    mitre: ['T1021.002', 'T1078', 'T1003.001'],
    createdBy: 'system',
    createdAt: new Date(now - 6 * 60 * 60 * 1000).toISOString(),
    updatedAt: new Date(now - 12 * 60 * 1000).toISOString(),
    dueAt: new Date(now + 18 * 60 * 60 * 1000).toISOString(),
    timeline: [
      {
        id: 'tl-1',
        type: 'created',
        timestamp: new Date(now - 6 * 60 * 60 * 1000).toISOString(),
        title: 'Case created from correlation rule',
        actor: 'system',
        description:
          'Rule "Lateral movement from privileged subnet" matched 3 alerts within 4 minutes.',
      },
      {
        id: 'tl-2',
        type: 'assigned',
        timestamp: new Date(now - 5 * 60 * 60 * 1000).toISOString(),
        title: 'Assigned to Sasha Lin',
        actor: 'andre.k',
      },
      {
        id: 'tl-3',
        type: 'agent',
        timestamp: new Date(now - 4 * 60 * 60 * 1000).toISOString(),
        title: 'Auto-investigation completed',
        actor: 'aisoc-agent',
        description:
          'Confirmed pivot via SMB. Recommend isolating WIN-FIN-DB01 and rotating service account creds.',
      },
      {
        id: 'tl-4',
        type: 'note',
        timestamp: new Date(now - 90 * 60 * 1000).toISOString(),
        title: 'Note added',
        actor: 'sasha.lin',
        description:
          'IT confirmed the service account belongs to the legacy backup tool. ' +
          'Proceeding to rotate creds and revoke session.',
      },
      {
        id: 'tl-5',
        type: 'status',
        timestamp: new Date(now - 12 * 60 * 1000).toISOString(),
        title: 'Status changed to In progress',
        actor: 'sasha.lin',
      },
    ],
    tasks: [
      {
        id: 'task-1',
        title: 'Isolate WIN-FIN-DB01 from network',
        status: 'done',
        assignee: 'andre.k',
        createdAt: new Date(now - 3 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: 'task-2',
        title: 'Rotate svc_backup credentials',
        status: 'in_progress',
        assignee: 'sasha.lin',
        createdAt: new Date(now - 2 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: 'task-3',
        title: 'Forensic image of BACKUP-SRV-12',
        status: 'todo',
        createdAt: new Date(now - 60 * 60 * 1000).toISOString(),
      },
    ],
  };
}

// ─── Style maps ───────────────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<CaseSeverity, string> = {
  critical: 'bg-red-500/15 text-red-300 ring-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 ring-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 ring-blue-500/30',
};

const STATUS_LABEL: Record<CaseStatus, string> = {
  open: 'Open',
  in_progress: 'In progress',
  pending: 'Pending',
  resolved: 'Resolved',
  closed: 'Closed',
};

const STATUS_DOT: Record<CaseStatus, string> = {
  open: 'bg-slate-400',
  in_progress: 'bg-blue-400 animate-pulse',
  pending: 'bg-amber-400',
  resolved: 'bg-emerald-400',
  closed: 'bg-slate-600',
};

const TASK_STATUS_BADGE: Record<CaseTask['status'], string> = {
  todo: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
  in_progress: 'bg-blue-500/15 text-blue-300 ring-blue-500/30',
  done: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30',
};

const TIMELINE_ICON: Record<string, string> = {
  created: 'new',
  assigned: 'asn',
  status: 'sts',
  note: 'note',
  agent: 'ai',
  comment: 'cmt',
  alert: 'alrt',
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatusPill({ status }: { status: CaseStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-700/70 bg-slate-800/40 px-2 py-0.5 text-xs font-medium text-slate-200">
      <span className={clsx('h-1.5 w-1.5 rounded-full', STATUS_DOT[status])} />
      {STATUS_LABEL[status]}
    </span>
  );
}

function MitreChip({ id }: { id: string }) {
  return (
    <a
      href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`}
      target="_blank"
      rel="noreferrer"
      className="rounded-full border border-orange-500/30 bg-orange-500/10 px-2 py-0.5 text-[11px] font-medium text-orange-300 transition-colors hover:bg-orange-500/20"
    >
      {id} ↗
    </a>
  );
}

function TimelineItem({ event }: { event: CaseTimelineEvent }) {
  const icon = TIMELINE_ICON[event.type] ?? '·';
  return (
    <li className="relative pl-10">
      <span className="absolute left-0 top-1 flex h-7 w-7 items-center justify-center rounded-full border border-slate-700/70 bg-slate-900 text-[10px] font-medium uppercase tracking-wide text-slate-400">
        {icon}
      </span>
      <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-3">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <p className="text-sm font-medium text-slate-100">{event.title}</p>
          {event.actor && (
            <span className="text-[11px] text-slate-500">by {event.actor}</span>
          )}
          <span className="ml-auto text-[11px] text-slate-500" suppressHydrationWarning>
            {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
          </span>
        </div>
        {event.description && (
          <p className="mt-1.5 text-xs text-slate-400">{event.description}</p>
        )}
      </div>
    </li>
  );
}

interface TaskRowProps {
  task: CaseTask;
  onChangeStatus: (status: CaseTask['status']) => void;
}

function TaskRow({ task, onChangeStatus }: TaskRowProps) {
  const next: CaseTask['status'] =
    task.status === 'todo'
      ? 'in_progress'
      : task.status === 'in_progress'
        ? 'done'
        : 'todo';

  return (
    <li className="flex items-start gap-2 rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2">
      <button
        onClick={() => onChangeStatus(next)}
        className={clsx(
          'mt-0.5 flex h-5 w-5 flex-none items-center justify-center rounded border text-[11px] transition-colors',
          task.status === 'done'
            ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
            : task.status === 'in_progress'
              ? 'border-blue-500/40 bg-blue-500/15 text-blue-300'
              : 'border-slate-600 text-slate-500 hover:border-slate-400',
        )}
        aria-label={`Mark task ${next}`}
        title={`Move to ${next}`}
      >
        {task.status === 'done' ? '✓' : task.status === 'in_progress' ? '·' : ''}
      </button>
      <div className="min-w-0 flex-1">
        <p
          className={clsx(
            'text-sm',
            task.status === 'done'
              ? 'text-slate-500 line-through'
              : 'text-slate-100',
          )}
        >
          {task.title}
        </p>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[11px] text-slate-500">
          <span
            className={clsx(
              'inline-flex items-center rounded px-1.5 py-0.5 ring-1',
              TASK_STATUS_BADGE[task.status],
            )}
          >
            {task.status.replace('_', ' ')}
          </span>
          {task.assignee && <span>@{task.assignee}</span>}
          <span suppressHydrationWarning>
            {formatDistanceToNow(new Date(task.createdAt), { addSuffix: true })}
          </span>
        </div>
      </div>
    </li>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export function CaseWorkspace({ caseId }: { caseId: string }) {
  const [demoMode, setDemoMode] = useState(false);
  // Honor `?tab=…` so the hosted demo deeplink
  // (`/cases/INC-RT-001?tab=ledger`) lands visitors directly on the live
  // agent decision feed for the LockBit 3.0 ransomware showcase. Falls back
  // to the overview when the param is missing or unrecognized.
  const searchParams = useSearchParams();
  const initialTab: WorkspaceTab = useMemo(() => {
    const t = searchParams?.get('tab') ?? null;
    return isWorkspaceTab(t) ? t : 'overview';
  }, [searchParams]);
  const [activeTab, setActiveTab] = useState<WorkspaceTab>(initialTab);
  const { data, error, isLoading, mutate } = useSWR<Case>(
    ['case', caseId],
    () => casesApi.get(caseId),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const useFallback = !!error;
  const caseRecord: Case | undefined = useMemo(() => {
    if (data) return data;
    if (useFallback) return buildDemoCase(caseId);
    return undefined;
  }, [data, useFallback, caseId]);

  // Track demo mode for the header banner. Calling setState during render is
  // a React anti-pattern that can interact badly with hydration; defer to an
  // effect so the first paint matches between server and client.
  useEffect(() => {
    if (useFallback && !demoMode) setDemoMode(true);
  }, [useFallback, demoMode]);

  // ─── Investigation state ───────────────────────────────────────────────────
  const [investigating, setInvestigating] = useState(false);
  const [investigationRunId, setInvestigationRunId] = useState<string | null>(null);
  const [investigationStatus, setInvestigationStatus] = useState<string>('idle');
  const [investigationData, setInvestigationData] = useState<Record<string, unknown> | null>(null);
  const [reportMd, setReportMd] = useState<string>('');
  const [liveSteps, setLiveSteps] = useState<Array<{ kind: string; agent: string; summary: string; ts: string }>>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const closeWs = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  useEffect(() => () => { stopPolling(); closeWs(); }, [stopPolling, closeWs]);

  /** Connect to the realtime service WebSocket for this run_id */
  const connectWs = useCallback((runId: string) => {
    closeWs();
    // Mint a short-lived ticket and attach it as `?token=` before opening the
    // socket (Issue #239). The realtime service rejects tokenless upgrades and
    // derives the tenant from the verified claim, so we no longer send a
    // client-chosen `tenant_id`. On failure (signed-out / ticketing not
    // configured) we silently fall back to the polling loop already running.
    void (async () => {
      let token: string;
      try {
        ({ token } = await realtimeApi.ticket());
      } catch {
        // Could not authenticate — polling fallback covers live updates.
        return;
      }
      const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
      // The Next.js dev server proxies /ws → realtime service on :8086.
      // In production, nginx handles the proxy.
      const wsUrl = `${wsProto}://${window.location.host}/ws/agents?token=${encodeURIComponent(token)}`;
      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;
        ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data as string) as Record<string, unknown>;
          const msgRunId = msg.run_id as string | undefined;
          // Only process events for this run
          if (msgRunId && msgRunId !== runId) return;

          if (msg.type === 'agent.event') {
            const kind = (msg.kind ?? '') as string;
            const agent = (msg.agent ?? '') as string;
            const summary = (msg.summary ?? '') as string;
            const ts = (msg.timestamp ?? new Date().toISOString()) as string;

            setLiveSteps((prev) => [...prev, { kind, agent, summary, ts }]);

            if (kind === 'completed') {
              setInvestigationStatus('completed');
              setInvestigating(false);
              toast.success('Investigation complete — report ready');
              // Fetch the Markdown report
              fetch(`/api/v1/cases/${caseId}/investigations/${runId}/report.md`)
                .then((r) => r.ok ? r.text() : '')
                .then((md) => { if (md) setReportMd(md); })
                .catch(() => { /* best-effort */ });
              // Also fetch full data
              casesApi.getInvestigation(caseId, runId)
                .then((inv) => setInvestigationData(inv as Record<string, unknown>))
                .catch(() => { /* best-effort */ });
              closeWs();
            } else if (kind === 'error') {
              setInvestigationStatus('failed');
              setInvestigating(false);
              toast.error(`Investigation failed: ${summary}`);
              closeWs();
            }
          }
        } catch { /* ignore parse errors */ }
      };
      ws.onerror = () => {
        // Fall back to polling if WebSocket fails
        ws.close();
        wsRef.current = null;
      };
      } catch {
        // WebSocket not available — polling fallback is already running
      }
    })();
  }, [caseId, closeWs]);

  const startInvestigation = useCallback(async () => {
    if (!caseRecord || investigating) return;
    setInvestigating(true);
    setInvestigationStatus('starting');
    setLiveSteps([]);
    setActiveTab('investigation');
    try {
      const result = await casesApi.investigate(caseId, caseRecord.description ?? caseRecord.title);
      setInvestigationRunId(result.run_id);
      setInvestigationStatus('running');
      toast.success('Agent investigation started');

      // Connect via WebSocket for live updates (falls back to polling on error)
      connectWs(result.run_id);

      // Polling as a reliable fallback / data sync
      pollRef.current = setInterval(async () => {
        try {
          const inv = await casesApi.getInvestigation(caseId, result.run_id);
          setInvestigationData(inv as Record<string, unknown>);
          setInvestigationStatus(inv.status);
          if (inv.status === 'completed' || inv.status === 'failed') {
            stopPolling();
            setInvestigating(false);
            if (inv.status === 'completed') {
              toast.success('Investigation complete — report ready');
              try {
                const resp = await fetch(`/api/v1/cases/${caseId}/investigations/${result.run_id}/report.md`);
                if (resp.ok) setReportMd(await resp.text());
              } catch { /* best-effort */ }
            } else {
              toast.error(`Investigation failed: ${inv.error ?? 'unknown error'}`);
            }
          }
        } catch {
          // swallow transient errors
        }
      }, 5000);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Backend offline';
      toast(`Demo mode: investigation not available (${message})`);
      // Set demo investigation result
      setInvestigationStatus('completed');
      setInvestigationData({
        status: 'completed',
        recon: { iocs: [{ type: 'ip', value: '192.168.1.105' }, { type: 'domain', value: 'c2.evil-corp.io' }], mitre_techniques: ['T1021.002', 'T1078'], summary: 'Lateral movement via SMB with stolen credentials. C2 domain identified.' },
        forensic: { timeline: [{ ts: new Date().toISOString(), event: 'SMB connection from FIN-DB01 to BACKUP-SRV-12' }], root_cause_hypothesis: 'Compromised svc_backup service account used for lateral movement.', confidence: 0.88, summary: 'High confidence lateral movement chain identified.' },
        responder: { recommended_actions: ['Isolate WIN-FIN-DB01', 'Rotate svc_backup credentials', 'Block C2 domain at perimeter'], risk_level: 'high', dry_run: true, summary: 'Containment actions generated (dry-run only — review before executing).' },
        audit_log: [{ kind: 'recon', agent: 'ReconAgent', summary: 'Found 2 IOCs, 2 MITRE techniques in 1200ms', ts: new Date().toISOString() }, { kind: 'forensic', agent: 'ForensicAgent', summary: 'Timeline: 1 events, confidence 88%', ts: new Date().toISOString() }, { kind: 'responder', agent: 'ResponderAgent', summary: 'Generated 3 recommended actions (risk=high, dry_run=True)', ts: new Date().toISOString() }, { kind: 'report', agent: 'ReportWriterAgent', summary: 'Report written (1240 chars)', ts: new Date().toISOString() }],
      });
      setReportMd(`# Incident Report — ${caseRecord.title}\n\n**Generated by AiSOC AI Investigator (demo mode)**\n\n## Executive Summary\nLateral movement confirmed from WIN-FIN-DB01 to BACKUP-SRV-12 via compromised service account credentials.\n\n## IOCs\n- 192.168.1.105 (internal pivot source)\n- c2.evil-corp.io (C2 domain)\n\n## MITRE ATT&CK\n- T1021.002 — SMB/Windows Admin Shares\n- T1078 — Valid Accounts\n\n## Recommended Actions\n1. Isolate WIN-FIN-DB01 from network\n2. Rotate svc_backup credentials immediately\n3. Block c2.evil-corp.io at perimeter firewall\n\n---\n*This is a demo report generated without a live backend.*`);
      setInvestigating(false);
    }
  }, [caseRecord, caseId, investigating, stopPolling]);

  // ─── Local mutations (optimistic) ──────────────────────────────────────────

  const [newComment, setNewComment] = useState('');
  const [newTask, setNewTask] = useState('');
  const [statusUpdating, setStatusUpdating] = useState(false);
  // WS-D2 — track summary-download state so the button can show "Generating…"
  // and we can surface failures via toast without burying them in the console.
  const [summaryDownloading, setSummaryDownloading] = useState(false);

  const downloadSummary = useCallback(async () => {
    if (!caseRecord || summaryDownloading) return;
    setSummaryDownloading(true);
    try {
      await casesApi.openAutoSummaryHtml(caseRecord.id || caseId);
      toast.success('Summary opened — use Print → Save as PDF to archive');
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Backend offline';
      toast.error(`Summary unavailable: ${message}`);
    } finally {
      setSummaryDownloading(false);
    }
  }, [caseRecord, caseId, summaryDownloading]);

  const updateStatus = async (status: CaseStatus) => {
    if (!caseRecord) return;
    setStatusUpdating(true);
    void mutate({ ...caseRecord, status }, { revalidate: false });
    try {
      await casesApi.update(caseRecord.id, { status });
      toast.success(`Status set to ${STATUS_LABEL[status]}`);
    } catch {
      toast(`Demo: status set to ${STATUS_LABEL[status]} locally (writes disabled)`);
    } finally {
      setStatusUpdating(false);
    }
  };

  const addComment = async () => {
    const trimmed = newComment.trim();
    if (!caseRecord || !trimmed) return;
    const optimistic: CaseTimelineEvent = {
      id: `tl-tmp-${Date.now()}`,
      type: 'comment',
      timestamp: new Date().toISOString(),
      title: 'Comment',
      description: trimmed,
      actor: 'you',
    };
    void mutate(
      { ...caseRecord, timeline: [...(caseRecord.timeline ?? []), optimistic] },
      { revalidate: false },
    );
    setNewComment('');
    try {
      await casesApi.addComment(caseRecord.id, trimmed);
      toast.success('Comment added');
    } catch {
      toast('Saved locally (writes disabled in demo)');
    }
  };

  const addTask = async () => {
    const trimmed = newTask.trim();
    if (!caseRecord || !trimmed) return;
    const optimistic: CaseTask = {
      id: `task-tmp-${Date.now()}`,
      title: trimmed,
      status: 'todo',
      createdAt: new Date().toISOString(),
    };
    void mutate(
      { ...caseRecord, tasks: [...(caseRecord.tasks ?? []), optimistic] },
      { revalidate: false },
    );
    setNewTask('');
    try {
      await casesApi.addTask(caseRecord.id, optimistic);
      toast.success('Task added');
    } catch {
      toast('Saved locally (writes disabled in demo)');
    }
  };

  const updateTaskStatus = async (
    taskId: string,
    status: CaseTask['status'],
  ) => {
    if (!caseRecord) return;
    const tasks = (caseRecord.tasks ?? []).map((t) =>
      t.id === taskId ? { ...t, status } : t,
    );
    void mutate({ ...caseRecord, tasks }, { revalidate: false });
    try {
      await casesApi.updateTask(caseRecord.id, taskId, { status });
    } catch {
      // already optimistically applied; nothing to do
    }
  };

  // ─── Render ────────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-12 w-2/3 rounded-lg" />
        <Skeleton className="h-32 w-full rounded-lg" />
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Skeleton className="h-96 w-full rounded-lg" />
          <Skeleton className="h-96 w-full rounded-lg lg:col-span-2" />
        </div>
      </div>
    );
  }

  if (!caseRecord) {
    return (
      <ErrorState
        title="Couldn't load case"
        error={error}
        onRetry={() => void mutate()}
        action={
          <Link
            href="/cases"
            className="rounded-md border border-slate-700/70 bg-slate-800/50 px-3 py-1.5 text-sm font-medium text-slate-200 hover:border-slate-600"
          >
            Back to cases
          </Link>
        }
      />
    );
  }

  const sortedTimeline = [...(caseRecord.timeline ?? [])].sort(
    (a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  );

  const tasks = caseRecord.tasks ?? [];
  const tasksDone = tasks.filter((t) => t.status === 'done').length;
  const tasksProgress = tasks.length === 0 ? 0 : Math.round((tasksDone / tasks.length) * 100);

  return (
    <div className="space-y-5">
      {/* Breadcrumb + demo banner */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs">
          <Link href="/cases" className="text-slate-500 hover:text-slate-300">
            Cases
          </Link>
          <span className="text-slate-600">/</span>
          <span className="font-mono text-slate-400">{caseRecord.id}</span>
        </div>
        {demoMode && (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-300 ring-1 ring-amber-500/30">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
            Demo data — writes disabled
          </span>
        )}
      </div>

      {/* Header */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={clsx(
                  'inline-flex items-center rounded px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ring-1',
                  SEVERITY_BADGE[caseRecord.severity],
                )}
              >
                {caseRecord.severity}
              </span>
              <StatusPill status={caseRecord.status} />
              {caseRecord.tags?.map((t) => (
                <span
                  key={t}
                  className="rounded bg-slate-800/60 px-2 py-0.5 text-[11px] text-slate-300"
                >
                  #{t}
                </span>
              ))}
            </div>
            <h1 className="mt-2 text-xl font-semibold text-white">
              {caseRecord.title}
            </h1>
            {caseRecord.description && (
              <p className="mt-2 max-w-3xl text-sm text-slate-400">
                {caseRecord.description}
              </p>
            )}
            {caseRecord.mitre && caseRecord.mitre.length > 0 && (
              <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs">
                <span className="text-slate-500">MITRE ATT&CK:</span>
                {caseRecord.mitre.map((m) => (
                  <MitreChip key={m} id={m} />
                ))}
              </div>
            )}
          </div>

          {/* Action bar */}
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={caseRecord.status}
              onChange={(e) => void updateStatus(e.target.value as CaseStatus)}
              disabled={statusUpdating}
              className="rounded-md border border-slate-700/70 bg-slate-900/60 px-2 py-1.5 text-xs text-slate-200 focus:border-emerald-500/40 focus:outline-none"
            >
              {(['open', 'in_progress', 'pending', 'resolved', 'closed'] as CaseStatus[]).map(
                (s) => (
                  <option key={s} value={s}>
                    {STATUS_LABEL[s]}
                  </option>
                ),
              )}
            </select>
            <button
              onClick={() => void startInvestigation()}
              disabled={investigating}
              className={clsx(
                'inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-semibold transition-colors',
                investigating
                  ? 'cursor-not-allowed border-slate-700/40 bg-slate-800/40 text-slate-500'
                  : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20',
              )}
            >
              {investigating && (
                <span className="h-3 w-3 animate-spin rounded-full border border-emerald-500/30 border-t-emerald-400" />
              )}
              {investigating ? 'Investigating…' : 'Investigate with agent'}
            </button>
            {/*
              WS-D2 — deterministic, analyst-ready snapshot of the entire case
              (lifecycle, MITRE coverage, observables, evidence, timeline,
              recommendations). Backed by `GET /cases/{id}/summary?format=html`
              which renders a self-contained, print-ready HTML document the
              analyst can save as PDF for compliance / handoff. Available on
              every case so analysts can grab a snapshot any time, but the
              backend also auto-emits a system breadcrumb when status flips to
              resolved/closed.
            */}
            <button
              onClick={() => void downloadSummary()}
              disabled={summaryDownloading || !caseRecord}
              className={clsx(
                'inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-semibold transition-colors',
                summaryDownloading || !caseRecord
                  ? 'cursor-not-allowed border-slate-700/40 bg-slate-800/40 text-slate-500'
                  : 'border-indigo-500/40 bg-indigo-500/10 text-indigo-200 hover:bg-indigo-500/20',
              )}
              title="Open a print-ready case summary (HTML → Save as PDF)"
            >
              {summaryDownloading && (
                <span className="h-3 w-3 animate-spin rounded-full border border-indigo-500/30 border-t-indigo-400" />
              )}
              {summaryDownloading ? 'Generating…' : 'Summary'}
            </button>
          </div>
        </div>

        {/* Meta row */}
        <div className="mt-4 grid grid-cols-2 gap-2 border-t border-slate-800/60 pt-4 text-xs text-slate-400 sm:grid-cols-4">
          <Meta label="Assignee" value={caseRecord.assignee?.split('@')[0] ?? '—'} />
          <Meta
            label="Created"
            value={format(new Date(caseRecord.createdAt), 'MMM d, HH:mm')}
            suppressHydrationWarning
          />
          <Meta
            label="Updated"
            value={formatDistanceToNow(new Date(caseRecord.updatedAt), {
              addSuffix: true,
            })}
            suppressHydrationWarning
          />
          <Meta
            label="SLA"
            value={
              caseRecord.dueAt
                ? `${formatDistanceToNow(new Date(caseRecord.dueAt))} left`
                : '—'
            }
            suppressHydrationWarning
          />
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-slate-800/70 text-xs">
        {VALID_TABS.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={clsx(
              'relative px-3 py-2 font-medium capitalize transition-colors',
              activeTab === tab
                ? 'text-emerald-300'
                : 'text-slate-500 hover:text-slate-300',
            )}
          >
            {tab === 'investigation' && investigating && (
              <span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
            )}
            {tab === 'ledger' ? (
              <span className="inline-flex items-center gap-1">
                Ledger
                <span
                  className="rounded bg-emerald-500/15 px-1 py-0.5 text-[8px] font-bold uppercase tracking-wider text-emerald-300 ring-1 ring-emerald-500/30"
                  title="Auditable agent decision log — every prompt, tool call, and decision is durably stored and replayable forever"
                >
                  audit
                </span>
              </span>
            ) : tab === 'attack-path' ? (
              <span className="inline-flex items-center gap-1">
                Attack path
                <span
                  className="rounded bg-orange-500/15 px-1 py-0.5 text-[8px] font-bold uppercase tracking-wider text-orange-300 ring-1 ring-orange-500/30"
                  title="Reconstructed attack graph from the Attack-Path Investigation Agent"
                >
                  graph
                </span>
              </span>
            ) : tab === 'attack-chain' ? (
              <span className="inline-flex items-center gap-1">
                Attack chain
                <span
                  className="rounded bg-rose-500/15 px-1 py-0.5 text-[8px] font-bold uppercase tracking-wider text-rose-300 ring-1 ring-rose-500/30"
                  title="Ranked temporal timeline of related alerts that form the attack chain"
                >
                  timeline
                </span>
              </span>
            ) : (
              tab
            )}
            {activeTab === tab && (
              <span className="absolute inset-x-0 bottom-0 h-px bg-emerald-400" />
            )}
          </button>
        ))}
      </div>

      {/* Investigation tab */}
      {activeTab === 'investigation' && (
        <InvestigationPanel
          status={investigationStatus}
          data={investigationData}
          liveSteps={liveSteps}
          onViewReport={() => setActiveTab('report')}
        />
      )}

      {/* Attack path tab — reconstructed graph for this case.
          We use the URL `caseId` prop rather than `caseRecord.id` because some
          backend variants return the case body without an `id` field; the URL
          is the canonical identifier here. */}
      {activeTab === 'attack-path' && (
        <AttackPathPanel caseId={caseRecord.id || caseId} />
      )}

      {/* Attack-chain tab — ranked temporal timeline of related alerts */}
      {activeTab === 'attack-chain' && (
        <AttackChainPanel caseId={caseRecord.id || caseId} />
      )}

      {/* Ledger tab — persistent, replayable agent decision log */}
      {activeTab === 'ledger' && (
        <InvestigationLedger
          caseId={caseRecord.id || caseId}
          activeRunId={investigationRunId}
          onSelectRun={(rid) => setInvestigationRunId(rid)}
        />
      )}

      {/* Report tab */}
      {activeTab === 'report' && (
        <ReportPanel
          markdown={reportMd}
          caseId={caseRecord.id || caseId}
          runId={investigationRunId ?? ''}
        />
      )}

      {/* Overview: Three-pane layout */}
      {activeTab === 'overview' && (
      <div className="space-y-4">
        {/*
          Ambient Copilot — case-scoped contextual AI. We pass a compact
          snapshot of the case (no embedded alert blobs or full timeline) so the
          LLM has grounding without ballooning token usage. Backed by
          `services/agents` `/api/v1/contextual` endpoints.
        */}
        <ContextualActions
          page="cases"
          entityId={caseRecord.id}
          caseId={caseRecord.id}
          entity={{
            title: caseRecord.title,
            description: caseRecord.description,
            severity: caseRecord.severity,
            status: caseRecord.status,
            assignee: caseRecord.assignee,
            mitre: caseRecord.mitre,
            tags: caseRecord.tags,
            alert_ids: caseRecord.alertIds,
            alert_count: caseRecord.alertCount,
            created_at: caseRecord.createdAt,
            updated_at: caseRecord.updatedAt,
            due_at: caseRecord.dueAt,
          }}
          eyebrow="Ask AiSOC about this case"
        />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
        {/* Left: Linked alerts + IOCs */}
        <aside className="lg:col-span-3 space-y-4">
          <Panel title={`Linked alerts (${caseRecord.alertIds?.length ?? 0})`}>
            {(caseRecord.alertIds ?? []).length === 0 ? (
              <EmptyState
                title="No alerts linked"
                description="Link alerts from the alerts feed."
              />
            ) : (
              <ul className="space-y-1.5">
                {(caseRecord.alertIds ?? []).map((id) => (
                  <li key={id}>
                    <Link
                      href={`/alerts?focus=${encodeURIComponent(id)}`}
                      className="flex items-center justify-between rounded-md border border-slate-800/80 bg-slate-900/40 px-2.5 py-1.5 text-xs text-slate-300 transition-colors hover:border-slate-700 hover:bg-slate-800/40"
                    >
                      <span className="font-mono">{id}</span>
                      <span className="text-[10px] uppercase tracking-wide text-slate-500">open</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel title="Tasks">
            <div className="mb-2 flex items-center gap-2 text-[11px] text-slate-400">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-emerald-500 transition-all"
                  style={{ width: `${tasksProgress}%` }}
                />
              </div>
              <span>
                {tasksDone}/{tasks.length}
              </span>
            </div>
            {tasks.length === 0 ? (
              <EmptyState title="No tasks yet" description="Add the first one below." />
            ) : (
              <ul className="space-y-1.5">
                {tasks.map((t) => (
                  <TaskRow
                    key={t.id}
                    task={t}
                    onChangeStatus={(s) => void updateTaskStatus(t.id, s)}
                  />
                ))}
              </ul>
            )}
            <div className="mt-2 flex items-center gap-2">
              <input
                value={newTask}
                onChange={(e) => setNewTask(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void addTask();
                }}
                placeholder="Add task and press ↵"
                className="flex-1 rounded-md border border-slate-700/70 bg-slate-900/40 px-2 py-1.5 text-xs text-slate-100 placeholder-slate-600 focus:border-emerald-500/40 focus:outline-none"
              />
              <button
                onClick={() => void addTask()}
                className="rounded-md bg-emerald-500 px-2.5 py-1.5 text-xs font-semibold text-emerald-950 transition-colors hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
                disabled={!newTask.trim()}
              >
                Add
              </button>
            </div>
          </Panel>
        </aside>

        {/* Center: Timeline */}
        <section className="lg:col-span-6">
          <Panel
            title="Timeline"
            actions={
              <span className="text-[11px] text-slate-500">
                {sortedTimeline.length} events
              </span>
            }
          >
            {sortedTimeline.length === 0 ? (
              <EmptyState
                title="Quiet so far"
                description="Activity, comments, and agent runs will appear here."
              />
            ) : (
              <ol className="relative space-y-3 before:absolute before:left-3.5 before:top-2 before:bottom-2 before:w-px before:bg-slate-800/80">
                {sortedTimeline.map((e) => (
                  <TimelineItem key={e.id} event={e} />
                ))}
              </ol>
            )}
          </Panel>
        </section>

        {/* Right: Notes / activity composer */}
        <aside className="lg:col-span-3 space-y-4">
          <Panel title="Notes & comments">
            <div className="space-y-2">
              <textarea
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                rows={4}
                placeholder="Drop your findings, IOCs, or next steps…"
                className="w-full resize-none rounded-md border border-slate-700/70 bg-slate-900/40 px-2 py-1.5 text-xs text-slate-100 placeholder-slate-600 focus:border-emerald-500/40 focus:outline-none"
              />
              <div className="flex items-center justify-end gap-2">
                <button
                  onClick={() => setNewComment('')}
                  className="rounded-md border border-slate-700/70 px-2.5 py-1.5 text-xs text-slate-300 hover:border-slate-600"
                >
                  Clear
                </button>
                <button
                  onClick={() => void addComment()}
                  disabled={!newComment.trim()}
                  className="rounded-md bg-emerald-500 px-2.5 py-1.5 text-xs font-semibold text-emerald-950 transition-colors hover:bg-emerald-400 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
                >
                  Post
                </button>
              </div>
            </div>
          </Panel>

          <Panel title="Resolution">
            <textarea
              defaultValue={caseRecord.resolution ?? ''}
              rows={5}
              placeholder="Final summary, root cause, remediation…"
              className="w-full resize-none rounded-md border border-slate-700/70 bg-slate-900/40 px-2 py-1.5 text-xs text-slate-100 placeholder-slate-600 focus:border-emerald-500/40 focus:outline-none"
            />
          </Panel>
        </aside>
      </div>
      </div>
      )}
    </div>
  );
}

// ─── Investigation panel ──────────────────────────────────────────────────────

type LiveStep = { kind: string; agent: string; summary: string; ts: string };

function InvestigationPanel({
  status,
  data,
  liveSteps,
  onViewReport,
}: {
  status: string;
  data: Record<string, unknown> | null;
  liveSteps: LiveStep[];
  onViewReport: () => void;
}) {
  if (status === 'idle' || status === 'starting') {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/60 bg-slate-900/30 py-16 text-center">
        <p className="text-sm font-medium text-slate-300">Agent investigation</p>
        <p className="mt-1 max-w-md text-xs text-slate-500">
          Use &ldquo;Investigate with agent&rdquo; in the header to run the recon, forensic, and responder agents on this case.
        </p>
      </div>
    );
  }

  if (status === 'running') {
    return (
      <div className="rounded-xl border border-slate-800/70 bg-slate-900/30 p-5 space-y-4">
        <div className="flex items-center gap-3">
          <span className="h-7 w-7 animate-spin rounded-full border-2 border-emerald-500/30 border-t-emerald-400 shrink-0" />
          <div>
            <p className="text-sm font-medium text-slate-300">Investigation in progress…</p>
            <p className="text-xs text-slate-500">Agents are working. Steps appear below in real-time.</p>
          </div>
        </div>
        {liveSteps.length > 0 && (
          <LiveStepsFeed steps={liveSteps} />
        )}
      </div>
    );
  }

  if (status === 'failed') {
    return (
      <div className="rounded-xl border border-red-800/40 bg-red-900/10 p-5">
        <p className="text-sm font-semibold text-red-300">Investigation failed</p>
        <p className="mt-1 text-xs text-slate-400">{String((data as { error?: string })?.error ?? 'Unknown error')}</p>
        {liveSteps.length > 0 && (
          <div className="mt-3">
            <LiveStepsFeed steps={liveSteps} />
          </div>
        )}
      </div>
    );
  }

  // completed
  const recon = data?.recon as Record<string, unknown> | undefined;
  const forensic = data?.forensic as Record<string, unknown> | undefined;
  const responder = data?.responder as Record<string, unknown> | undefined;
  const auditLog = liveSteps.length > 0
    ? liveSteps
    : (data?.audit_log as Array<{ kind: string; agent: string; summary: string }>) ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-300 ring-1 ring-emerald-500/30">
          Investigation complete
        </span>
        <button
          onClick={onViewReport}
          className="rounded-md border border-slate-700/70 bg-slate-800/50 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-600"
        >
          View full report
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Recon */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-blue-300">Recon</h4>
          {recon?.summary != null && <p className="text-xs text-slate-400">{String(recon.summary)}</p>}
          {Array.isArray(recon?.iocs) && recon.iocs.length > 0 && (
            <div>
              <p className="text-[11px] text-slate-500 mb-1">IOCs found:</p>
              <ul className="space-y-0.5">
                {(recon.iocs as Array<{ type: string; value: string }>).slice(0, 5).map((ioc) => (
                  <li key={ioc.value} className="text-[11px] font-mono text-slate-300">
                    <span className="text-slate-500">[{ioc.type}]</span> {ioc.value}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {Array.isArray(recon?.mitre_techniques) && recon.mitre_techniques.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {(recon.mitre_techniques as string[]).map((t) => (
                <span key={t} className="rounded bg-orange-500/10 px-1.5 py-0.5 text-[10px] text-orange-300 ring-1 ring-orange-500/20">{t}</span>
              ))}
            </div>
          )}
        </div>

        {/* Forensic */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-purple-300">Forensic</h4>
          {forensic?.summary != null && <p className="text-xs text-slate-400">{String(forensic.summary)}</p>}
          {forensic?.root_cause_hypothesis != null && (
            <div>
              <p className="text-[11px] text-slate-500">Root cause hypothesis:</p>
              <p className="text-xs text-slate-300">{String(forensic.root_cause_hypothesis)}</p>
            </div>
          )}
          {typeof forensic?.confidence === 'number' && (
            <div className="flex items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-slate-800">
                <div className="h-full rounded-full bg-purple-500" style={{ width: `${(forensic.confidence as number) * 100}%` }} />
              </div>
              <span className="text-[11px] text-slate-400">{Math.round((forensic.confidence as number) * 100)}% confidence</span>
            </div>
          )}
        </div>

        {/* Responder */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-amber-300">Response</h4>
          {responder?.summary != null && <p className="text-xs text-slate-400">{String(responder.summary)}</p>}
          {Array.isArray(responder?.recommended_actions) && (
            <ul className="space-y-1">
              {(responder.recommended_actions as string[]).slice(0, 4).map((action, i) => (
                <li key={i} className="flex items-start gap-1.5 text-xs text-slate-300">
                  <span className="mt-0.5 h-1.5 w-1.5 flex-none rounded-full bg-amber-400" />
                  {action}
                </li>
              ))}
            </ul>
          )}
          {responder?.risk_level != null && (
            <span className={clsx(
              'inline-flex rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1',
              responder.risk_level === 'high' ? 'bg-red-500/10 text-red-300 ring-red-500/20' :
              responder.risk_level === 'medium' ? 'bg-amber-500/10 text-amber-300 ring-amber-500/20' :
              'bg-emerald-500/10 text-emerald-300 ring-emerald-500/20',
            )}>
              {String(responder.risk_level)} risk
            </span>
          )}
        </div>
      </div>

      {auditLog.length > 0 && (
        <details className="rounded-xl border border-slate-800/80">
          <summary className="cursor-pointer px-4 py-2 text-xs text-slate-400 hover:text-slate-200">
            Agent audit log ({auditLog.length} steps)
          </summary>
          <AuditLogPreview log={auditLog} />
        </details>
      )}
    </div>
  );
}

// ─── Attack path panel ────────────────────────────────────────────────────────

/**
 * AttackPathPanel renders the case-scoped attack-path graph reconstructed by
 * the Attack-Path Investigation Agent. Cases without graph entities (404 from
 * the backend) fall back to an explanatory empty state so the analyst knows
 * the agent is wired up but simply has no graph context yet.
 */
function AttackPathPanel({ caseId }: { caseId: string }) {
  // Guard: when caseId is falsy (router not yet hydrated, fallback path mid-build,
  // backend response without an id field) we render the empty state instead of
  // firing /api/v1/graph/attack-path/undefined which 500s and pollutes the UI.
  const hasCaseId = Boolean(caseId);
  const { data, error, isLoading } = useSWR<CaseAttackPath | null>(
    hasCaseId ? `case:${caseId}:attack-path` : null,
    () => graphApi.getCaseAttackPath(caseId, { maxDepth: 4 }),
    { revalidateOnFocus: false },
  );

  if (!hasCaseId) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/60 bg-slate-900/30 py-16 text-center">
        <p className="text-sm font-medium text-slate-300">Loading case context…</p>
        <p className="mt-1 max-w-md text-xs text-slate-500">
          The attack-path graph appears once the case is loaded.
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-32 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Failed to load attack path"
        description={error instanceof Error ? error.message : 'Unknown error'}
      />
    );
  }

  if (!data || data.nodeCount === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/60 bg-slate-900/30 py-16 text-center">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-orange-500/10 ring-1 ring-orange-500/30">
          <svg className="h-5 w-5 text-orange-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        </div>
        <p className="text-sm font-medium text-slate-300">No attack path yet</p>
        <p className="mt-1 max-w-md text-xs text-slate-500">
          The Attack-Path Investigation Agent reconstructs lateral movement and blast radius from linked alerts and graph entities. Run an investigation or link more alerts to surface a path here.
        </p>
      </div>
    );
  }

  // Bucket nodes by entity type so the panel reads as &ldquo;hosts /
  // identities / processes&rdquo; rather than an undifferentiated soup.
  const nodesByType = data.nodes.reduce<Record<string, CaseAttackPath['nodes']>>(
    (acc, node) => {
      const type = (node.properties?.type as string) ?? node.label ?? 'entity';
      (acc[type] ||= []).push(node);
      return acc;
    },
    {},
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-slate-200">Reconstructed attack path</h3>
          <p className="text-xs text-slate-500">
            {data.nodeCount} node{data.nodeCount === 1 ? '' : 's'} · {data.edgeCount} edge{data.edgeCount === 1 ? '' : 's'} · depth ≤ 4
          </p>
        </div>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-orange-500/10 px-2.5 py-0.5 text-xs font-medium text-orange-300 ring-1 ring-orange-500/30">
          attack path
        </span>
      </div>

      {/* Entities grouped by type — keeps the panel scannable even when the
          backend returns dense graphs (10s of nodes is normal). */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {Object.entries(nodesByType).map(([type, nodes]) => (
          <div
            key={type}
            className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4"
          >
            <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
              {type} ({nodes.length})
            </h4>
            <ul className="space-y-1.5">
              {nodes.slice(0, 8).map((node) => (
                <li
                  key={node.id}
                  className="flex items-start gap-2 text-xs"
                >
                  <span className="mt-0.5 inline-block h-1.5 w-1.5 rounded-full bg-orange-400/60 shrink-0" />
                  <div className="min-w-0">
                    <p className="truncate font-mono text-slate-300">{node.label || node.id}</p>
                    {typeof node.properties?.risk_score === 'number' && (
                      <p className="text-[10px] text-slate-500">
                        risk score: {(node.properties.risk_score as number).toFixed(2)}
                      </p>
                    )}
                  </div>
                </li>
              ))}
              {nodes.length > 8 && (
                <li className="text-[10px] italic text-slate-500">
                  +{nodes.length - 8} more
                </li>
              )}
            </ul>
          </div>
        ))}
      </div>

      {/* Edges — show the relationship verbs because that's what differentiates
          a benign topology snapshot from an actual attack chain. */}
      {data.edges.length > 0 && (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4">
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">
            Relationships
          </h4>
          <ul className="space-y-1">
            {data.edges.slice(0, 12).map((edge, i) => (
              <li key={`${edge.source}-${edge.target}-${i}`} className="flex items-center gap-2 text-[11px] font-mono">
                <span className="truncate text-slate-300">{edge.source}</span>
                <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-orange-300">
                  {edge.type}
                </span>
                <span className="truncate text-slate-300">{edge.target}</span>
              </li>
            ))}
            {data.edges.length > 12 && (
              <li className="text-[10px] italic text-slate-500">
                +{data.edges.length - 12} more relationships
              </li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

// ─── Attack chain panel ───────────────────────────────────────────────────────
//
// Renders the ranked temporal timeline of related alerts (the "attack chain")
// computed by services/api/app/services/attack_chain.py. The backend's BFS
// expands from the seed alert through the case's linked alerts, ranks each
// link by recency + shared-entity overlap + MITRE tactic co-occurrence, and
// hands us back a deterministic timeline plus the entity graph that connects
// the alerts. We render this as a vertical timeline (most-recent first by
// distance) with severity bands, score, and the entities each step shares
// with its predecessor — that's the part an analyst actually reads to decide
// "yes, this is one campaign, not three independent things."

const CHAIN_SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-rose-500/15 text-rose-300 ring-rose-500/30',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  low: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
  info: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
};

function severityChipClass(severity: string): string {
  return CHAIN_SEVERITY_STYLES[severity?.toLowerCase()] ?? CHAIN_SEVERITY_STYLES.info;
}

const CHAIN_WINDOWS: ReadonlyArray<{ value: AttackChainWindow; label: string }> = [
  { value: '1h', label: '1 h' },
  { value: '6h', label: '6 h' },
  { value: '24h', label: '24 h' },
  { value: '72h', label: '72 h' },
  { value: '7d', label: '7 d' },
  { value: '30d', label: '30 d' },
];

const CHAIN_WINDOW_VALUES: ReadonlySet<AttackChainWindow> = new Set(
  CHAIN_WINDOWS.map((w) => w.value),
);

function isAttackChainWindow(value: string | null | undefined): value is AttackChainWindow {
  return typeof value === 'string' && CHAIN_WINDOW_VALUES.has(value as AttackChainWindow);
}

// Default lookback for first-time loads. Picked to be wide enough that a
// case with linked alerts from a typical investigation horizon (the day
// before, an active shift) renders chain links instead of the empty state
// on first paint; analysts who want a tighter view narrow with the
// selector, and the choice is persisted on the URL via `?window=…`.
const DEFAULT_CHAIN_WINDOW: AttackChainWindow = '24h';

function AttackChainPanel({ caseId }: { caseId: string }) {
  // Mirror AttackPathPanel's guard: caseId can be empty during the brief window
  // between route hydration and the case fetch resolving. Calling the API with
  // `undefined` returns a 5xx and confuses analysts during the demo flow.
  const hasCaseId = Boolean(caseId);

  // Honor `?window=…` so a deep-link like
  // `/cases/INC-001?tab=attack-chain&window=24h` lands the analyst on
  // the same lookback the linker chose. Only the initial value is read
  // from search params; subsequent user selections write back through
  // `history.replaceState` (see `handleWindowChange`) so the choice
  // survives reload without coupling this panel to the next/navigation
  // router instance (which can be undefined in unit tests).
  const searchParams = useSearchParams();
  const initialWindow: AttackChainWindow = useMemo(() => {
    const raw = searchParams?.get('window') ?? null;
    return isAttackChainWindow(raw) ? raw : DEFAULT_CHAIN_WINDOW;
  }, [searchParams]);
  const [windowParam, setWindowParam] = useState<AttackChainWindow>(initialWindow);

  const handleWindowChange = useCallback((next: AttackChainWindow) => {
    setWindowParam(next);
    if (typeof window === 'undefined') return;
    try {
      const url = new URL(window.location.href);
      url.searchParams.set('window', next);
      window.history.replaceState({}, '', url.toString());
    } catch {
      // Best-effort URL sync; a malformed location shouldn't break the
      // panel. The state update above is the source of truth either way.
    }
  }, []);

  const { data, error, isLoading } = useSWR<AttackChainTimeline | null>(
    hasCaseId ? ['case:attack-chain', caseId, windowParam] : null,
    () => casesApi.getAttackChain(caseId, { window: windowParam }),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  if (!hasCaseId) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/60 bg-slate-900/30 py-16 text-center">
        <p className="text-sm font-medium text-slate-300">Loading case context…</p>
        <p className="mt-1 max-w-md text-xs text-slate-500">
          The attack-chain timeline appears once the case is loaded.
        </p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-24 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Failed to load attack chain"
        description={error instanceof Error ? error.message : 'Unknown error'}
      />
    );
  }

  // The backend returns a structurally-valid object with `seed_alert_id: null`
  // and an empty chain when the case has no linked alerts yet. casesApi
  // collapses that to `null` so the empty state here is unambiguous.
  if (!data || data.chain.length === 0) {
    return (
      <div className="space-y-3">
        <WindowSelector value={windowParam} onChange={handleWindowChange} />
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/60 bg-slate-900/30 py-16 text-center">
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-rose-500/10 ring-1 ring-rose-500/30">
            <svg className="h-5 w-5 text-rose-300" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <p className="text-sm font-medium text-slate-300">No attack chain yet</p>
          <p className="mt-1 max-w-md text-xs text-slate-500">
            An attack chain forms once two or more alerts in the {windowParam} window share
            entities or MITRE techniques. Link more alerts to the case or widen the window.
          </p>
        </div>
      </div>
    );
  }

  // Pre-compute confidence band so we can present "high" vs "exploratory"
  // distinctly — analysts treat a 0.4 chain very differently from a 0.85 chain.
  const confidencePct = Math.round(data.confidence * 100);
  const confidenceBand =
    data.confidence >= 0.75 ? 'high' : data.confidence >= 0.5 ? 'medium' : 'low';
  const confidenceClass =
    confidenceBand === 'high'
      ? 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30'
      : confidenceBand === 'medium'
        ? 'bg-amber-500/15 text-amber-300 ring-amber-500/30'
        : 'bg-slate-500/15 text-slate-300 ring-slate-500/30';

  const nodeCount = data.entityGraph.nodes.length;
  const edgeCount = data.entityGraph.edges.length;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-medium text-slate-200">Reconstructed attack chain</h3>
          <p className="text-xs text-slate-500">
            {data.chain.length} link{data.chain.length === 1 ? '' : 's'} · {nodeCount} entit
            {nodeCount === 1 ? 'y' : 'ies'} · {edgeCount} edge{edgeCount === 1 ? '' : 's'} · window {data.window}
          </p>
          {data.chainSignature && (
            <p className="mt-0.5 font-mono text-[10px] text-slate-600 truncate">
              signature: {data.chainSignature}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span
            className={clsx(
              'inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1',
              confidenceClass,
            )}
            title="Confidence is derived from average link score and chain length"
          >
            confidence {confidencePct}%
          </span>
          <WindowSelector value={windowParam} onChange={handleWindowChange} />
        </div>
      </div>

      {/* Vertical timeline. Steps are already sorted by event_time on the
          backend (oldest → newest); we render in that order so the analyst
          reads the chain the same way the campaign actually unfolded. */}
      <ol className="relative space-y-3 border-l border-slate-800/60 pl-5">
        {data.chain.map((link, index) => {
          const sevClass = severityChipClass(link.severity);
          const isFirst = index === 0;
          const dtMinutes = Math.round(link.dtSeconds / 60);
          const dtLabel =
            isFirst
              ? 'seed'
              : dtMinutes <= 0
                ? `+${Math.max(1, Math.round(link.dtSeconds))}s`
                : dtMinutes < 60
                  ? `+${dtMinutes}m`
                  : `+${(dtMinutes / 60).toFixed(1)}h`;
          return (
            <li key={link.alertId} className="relative">
              {/* Dot anchored to the spine */}
              <span
                className={clsx(
                  'absolute -left-[26px] top-2 inline-block h-2.5 w-2.5 rounded-full ring-2 ring-slate-950',
                  isFirst ? 'bg-rose-400' : 'bg-slate-500',
                )}
              />
              <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={clsx(
                          'inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1',
                          sevClass,
                        )}
                      >
                        {link.severity}
                      </span>
                      {isFirst && (
                        <span className="inline-flex items-center rounded-full bg-rose-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-rose-300 ring-1 ring-rose-500/30">
                          seed
                        </span>
                      )}
                      {link.connectorType && (
                        <span className="inline-flex items-center rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-400 ring-1 ring-slate-700/60">
                          {link.connectorType}
                        </span>
                      )}
                      <span className="text-[10px] font-mono text-slate-500" title="time since previous link">
                        Δt {dtLabel}
                      </span>
                    </div>
                    <p className="mt-1.5 text-sm font-medium text-slate-200 truncate" title={link.title}>
                      {link.title}
                    </p>
                    <p className="mt-0.5 text-[11px] text-slate-500">
                      {(() => {
                        try {
                          return `${format(new Date(link.eventTime), 'MMM d, HH:mm:ss')} · ${formatDistanceToNow(new Date(link.eventTime), { addSuffix: true })}`;
                        } catch {
                          return link.eventTime;
                        }
                      })()}
                    </p>
                  </div>
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    <span className="rounded-md bg-slate-800/60 px-2 py-0.5 text-[10px] font-mono text-slate-300 ring-1 ring-slate-700/60">
                      score {link.score.toFixed(2)}
                    </span>
                    <span className="text-[10px] text-slate-600">distance {link.distance}</span>
                  </div>
                </div>

                {/* Shared entities — the "why is this link in the chain"
                    explanation. Empty for the seed because there's no
                    predecessor to share with. */}
                {link.sharedEntities.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {link.sharedEntities.slice(0, 6).map((entity, i) => (
                      <span
                        key={`${entity.kind ?? 'entity'}-${entity.value ?? i}`}
                        className="inline-flex items-center gap-1 rounded bg-slate-800/70 px-1.5 py-0.5 text-[10px] font-mono text-slate-300 ring-1 ring-slate-700/60"
                        title={`Shared with previous link: ${entity.kind ?? ''}`}
                      >
                        <span className="text-slate-500">{entity.kind}</span>
                        <span>{entity.value}</span>
                      </span>
                    ))}
                    {link.sharedEntities.length > 6 && (
                      <span className="text-[10px] italic text-slate-500">
                        +{link.sharedEntities.length - 6} more
                      </span>
                    )}
                  </div>
                )}

                {/* MITRE techniques — gives the chain ATT&CK colour even when
                    titles are vague. Surface up to 4 to keep cards compact. */}
                {link.mitreTechniques.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {link.mitreTechniques.slice(0, 4).map((tech) => (
                      <span
                        key={tech}
                        className="inline-flex items-center rounded bg-purple-500/10 px-1.5 py-0.5 text-[10px] font-mono text-purple-300 ring-1 ring-purple-500/30"
                      >
                        {tech}
                      </span>
                    ))}
                    {link.mitreTechniques.length > 4 && (
                      <span className="text-[10px] italic text-slate-500">
                        +{link.mitreTechniques.length - 4} more
                      </span>
                    )}
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ol>

      {/* Entity graph summary. The case's attack-path tab renders the full
          graph; here we just call out the entities that actually appear in
          the chain itself so the analyst can scan them at a glance. */}
      {data.entityGraph.nodes.length > 0 && (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Entities in chain ({data.entityGraph.nodes.length})
            </h4>
            <span className="text-[10px] text-slate-500">
              {data.entityGraph.edges.length} connection{data.entityGraph.edges.length === 1 ? '' : 's'}
            </span>
          </div>
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {data.entityGraph.nodes.slice(0, 24).map((node) => (
              <li
                key={node.id}
                className="inline-flex items-center gap-1 rounded bg-slate-800/70 px-1.5 py-0.5 text-[10px] font-mono text-slate-300 ring-1 ring-slate-700/60"
                title={node.label ?? node.id}
              >
                <span className="text-slate-500">{node.kind}</span>
                <span className="truncate max-w-[160px]">{node.label ?? node.id}</span>
              </li>
            ))}
            {data.entityGraph.nodes.length > 24 && (
              <li className="text-[10px] italic text-slate-500 self-center">
                +{data.entityGraph.nodes.length - 24} more
              </li>
            )}
          </ul>
        </div>
      )}

      <p className="text-[10px] text-slate-600">
        Chain computed at{' '}
        {(() => {
          try {
            return format(new Date(data.generatedAt), 'MMM d, HH:mm:ss');
          } catch {
            return data.generatedAt;
          }
        })()}{' '}
        · seed alert{' '}
        <span className="font-mono">{data.seedAlertId}</span>
      </p>
    </div>
  );
}

function WindowSelector({
  value,
  onChange,
}: {
  value: AttackChainWindow;
  onChange: (next: AttackChainWindow) => void;
}) {
  return (
    <div
      className="inline-flex items-center rounded-md border border-slate-800/80 bg-slate-900/40 p-0.5"
      role="group"
      aria-label="Attack chain time window"
    >
      {CHAIN_WINDOWS.map((opt) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => onChange(opt.value)}
          className={clsx(
            'rounded px-2 py-1 text-[11px] font-medium transition',
            value === opt.value
              ? 'bg-slate-800 text-slate-100 ring-1 ring-slate-700/60'
              : 'text-slate-400 hover:text-slate-200',
          )}
          aria-pressed={value === opt.value}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

function AuditLogPreview({ log }: { log: Array<{ kind: string; agent: string; summary: string }> }) {
  return (
    <ul className="p-4 space-y-1.5">
      {log.map((entry, i) => (
        <li key={i} className="flex items-start gap-2 text-[11px]">
          <span className="font-mono text-slate-500">[{entry.kind}]</span>
          <span className="font-semibold text-slate-400">{entry.agent}:</span>
          <span className="text-slate-400">{entry.summary}</span>
        </li>
      ))}
    </ul>
  );
}

// ─── Live steps feed (real-time WebSocket updates) ────────────────────────────

const AGENT_LABELS: Record<string, string> = {
  recon: 'recon',
  forensic: 'forensic',
  responder: 'responder',
  report: 'report',
  completed: 'done',
  error: 'error',
};

function LiveStepsFeed({ steps }: { steps: LiveStep[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [steps.length]);

  return (
    <div className="rounded-lg border border-slate-800/60 bg-slate-950/60 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-slate-800/60">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
          Live agent steps
        </span>
        <span className="text-[10px] text-slate-600">{steps.length} events</span>
      </div>
      <ul className="max-h-56 overflow-y-auto divide-y divide-slate-800/40">
        {steps.map((step, i) => {
          const label = AGENT_LABELS[step.kind] ?? step.kind;
          return (
            <li key={i} className="flex items-start gap-2.5 px-3 py-2">
              <span className="shrink-0 mt-0.5 rounded border border-slate-700/60 bg-slate-900 px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wide text-slate-400">
                {label}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] font-semibold text-slate-300">{step.agent}</span>
                  <span className="text-[10px] text-slate-600 font-mono">[{step.kind}]</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{step.summary}</p>
              </div>
              <span className="shrink-0 text-[9px] text-slate-600 font-mono mt-0.5" suppressHydrationWarning>
                {new Date(step.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </span>
            </li>
          );
        })}
      </ul>
      <div ref={bottomRef} />
    </div>
  );
}

// ─── Report panel ─────────────────────────────────────────────────────────────

function ReportPanel({
  markdown,
  caseId,
  runId,
}: {
  markdown: string;
  caseId: string;
  runId: string;
}) {
  const [pdfDownloading, setPdfDownloading] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);

  const handleDownloadPdf = async () => {
    if (!runId) return;
    setPdfDownloading(true);
    setPdfError(null);
    try {
      await casesApi.downloadReportPdf(caseId, runId);
    } catch (err) {
      setPdfError(err instanceof Error ? err.message : 'PDF download failed');
    } finally {
      setPdfDownloading(false);
    }
  };

  if (!markdown) {
    return (
      <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/60 bg-slate-900/30 py-16 text-center">
        <p className="text-sm font-medium text-slate-300">No report yet</p>
        <p className="mt-1 text-xs text-slate-500">Run an investigation to generate a report.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-900/40">
      <div className="flex items-center justify-between border-b border-slate-800/80 px-4 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">Incident Report</h3>
        <div className="flex items-center gap-3">
          {/* Download Markdown */}
          <button
            onClick={() => {
              const blob = new Blob([markdown], { type: 'text/markdown' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'incident-report.md';
              a.click();
              URL.revokeObjectURL(url);
            }}
            className="text-[11px] text-slate-400 hover:text-slate-200"
          >
            Download .md
          </button>
          {/* Download PDF */}
          {runId && (
            <button
              onClick={handleDownloadPdf}
              disabled={pdfDownloading}
              className={clsx(
                'flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium transition-colors',
                pdfDownloading
                  ? 'cursor-not-allowed text-slate-500'
                  : 'bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/40',
              )}
            >
              {pdfDownloading ? (
                <>
                  <span className="inline-block h-2.5 w-2.5 animate-spin rounded-full border-2 border-indigo-400 border-t-transparent" />
                  Generating…
                </>
              ) : (
                <>Download PDF</>
              )}
            </button>
          )}
        </div>
      </div>
      {pdfError && (
        <div className="border-b border-red-900/40 bg-red-950/30 px-4 py-2 text-[11px] text-red-400">
          PDF error: {pdfError}
        </div>
      )}
      <pre className="overflow-auto whitespace-pre-wrap p-4 font-mono text-[11px] leading-relaxed text-slate-300">
        {markdown}
      </pre>
    </div>
  );
}

// ─── Tiny presentational helpers ──────────────────────────────────────────────

function Meta({ label, value, suppressHydrationWarning: shw }: { label: string; value: string; suppressHydrationWarning?: boolean }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-0.5 text-sm text-slate-200" suppressHydrationWarning={shw}>{value}</p>
    </div>
  );
}

function Panel({
  title,
  actions,
  children,
}: {
  title: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40">
      <div className="flex items-center justify-between border-b border-slate-800/80 px-3 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">
          {title}
        </h3>
        {actions}
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}
