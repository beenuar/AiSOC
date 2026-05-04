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
  type Case,
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

type WorkspaceTab = 'overview' | 'investigation' | 'ledger' | 'report';

const VALID_TABS: readonly WorkspaceTab[] = ['overview', 'investigation', 'ledger', 'report'];

function isWorkspaceTab(value: string | null): value is WorkspaceTab {
  return value !== null && (VALID_TABS as readonly string[]).includes(value);
}

// ─── Demo case ────────────────────────────────────────────────────────────────

function buildDemoCase(id: string): Case {
  const now = Date.now();
  return {
    id,
    title: 'Suspected lateral movement from finance subnet',
    description:
      "Multiple high-severity alerts indicate an attacker pivoted from " +
      "WIN-FIN-DB01 to BACKUP-SRV-12 using compromised service account credentials. " +
      "Behavior consistent with T1021.002 (SMB/Windows Admin Shares).",
    status: 'in_progress',
    severity: 'critical',
    assignee: 'sasha.lin@aisoc.dev',
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
        title: 'Status → In progress',
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
  created: '🆕',
  assigned: '👤',
  status: '🔄',
  note: '📝',
  agent: '🤖',
  comment: '💬',
  alert: '🚨',
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
  const icon = TIMELINE_ICON[event.type] ?? '•';
  return (
    <li className="relative pl-10">
      <span className="absolute left-0 top-1 flex h-7 w-7 items-center justify-center rounded-full border border-slate-700/70 bg-slate-900 text-sm">
        {icon}
      </span>
      <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-3">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <p className="text-sm font-medium text-slate-100">{event.title}</p>
          {event.actor && (
            <span className="text-[11px] text-slate-500">by {event.actor}</span>
          )}
          <span className="ml-auto text-[11px] text-slate-500">
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
          <span>
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
  // Honor `?tab=…` so the hosted demo deeplink (`/cases/INC-001?tab=ledger`)
  // lands visitors directly on the live agent decision feed. Falls back to
  // the overview when the param is missing or unrecognized.
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

  // Track demo mode for the header banner.
  if (useFallback && !demoMode) setDemoMode(true);

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
  const connectWs = useCallback((runId: string, tenantId = 'default') => {
    closeWs();
    // Determine WS URL: same host, realtime port or proxied
    const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    // The Next.js dev server proxies /ws → realtime service on :8086
    // In production, nginx handles the proxy.
    const wsUrl = `${wsProto}://${window.location.host}/ws/agents?tenant_id=${tenantId}`;
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
              toast.success('Investigation complete — report ready!', { icon: '📋' });
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
      toast.success('AI investigation launched!', { icon: '🤖' });

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
              toast.success('Investigation complete — report ready!', { icon: '📋' });
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
      toast(`Demo mode: investigation not available (${message})`, { icon: '⚠️' });
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

  const updateStatus = async (status: CaseStatus) => {
    if (!caseRecord) return;
    setStatusUpdating(true);
    void mutate({ ...caseRecord, status }, { revalidate: false });
    try {
      await casesApi.update(caseRecord.id, { status });
      toast.success(`Status → ${STATUS_LABEL[status]}`);
    } catch {
      toast(
        `Demo: status set to ${STATUS_LABEL[status]} locally (backend offline)`,
        { icon: '⚠️' },
      );
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
      toast('Saved locally (backend offline)', { icon: '📝' });
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
      toast('Saved locally (backend offline)', { icon: '✓' });
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
            Demo data — backend offline
          </span>
        )}
      </div>

      {/* Header */}
      <div className="rounded-xl border border-slate-800/80 bg-gradient-to-br from-slate-900/60 via-slate-900/40 to-slate-900/20 p-5">
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
              {investigating ? 'Investigating…' : '🤖 Investigate with AI'}
            </button>
          </div>
        </div>

        {/* Meta row */}
        <div className="mt-4 grid grid-cols-2 gap-2 border-t border-slate-800/60 pt-4 text-xs text-slate-400 sm:grid-cols-4">
          <Meta label="Assignee" value={caseRecord.assignee?.split('@')[0] ?? '—'} />
          <Meta
            label="Created"
            value={format(new Date(caseRecord.createdAt), 'MMM d, HH:mm')}
          />
          <Meta
            label="Updated"
            value={formatDistanceToNow(new Date(caseRecord.updatedAt), {
              addSuffix: true,
            })}
          />
          <Meta
            label="SLA"
            value={
              caseRecord.dueAt
                ? `${formatDistanceToNow(new Date(caseRecord.dueAt))} left`
                : '—'
            }
          />
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-slate-800/70 text-xs">
        {(['overview', 'investigation', 'ledger', 'report'] as WorkspaceTab[]).map((tab) => (
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

      {/* Ledger tab — persistent, replayable agent decision log */}
      {activeTab === 'ledger' && (
        <InvestigationLedger
          caseId={caseRecord.id}
          activeRunId={investigationRunId}
          onSelectRun={(rid) => setInvestigationRunId(rid)}
        />
      )}

      {/* Report tab */}
      {activeTab === 'report' && (
        <ReportPanel
          markdown={reportMd}
          caseId={caseRecord.id}
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
                      <span className="text-slate-500">→</span>
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
        <span className="text-3xl">🤖</span>
        <p className="mt-3 text-sm font-medium text-slate-300">AI Investigation</p>
        <p className="mt-1 text-xs text-slate-500">
          Click &ldquo;Investigate with AI&rdquo; in the header to launch the autonomous investigator.
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
          ✓ Investigation complete
        </span>
        <button
          onClick={onViewReport}
          className="rounded-md border border-slate-700/70 bg-slate-800/50 px-3 py-1.5 text-xs font-medium text-slate-200 hover:border-slate-600"
        >
          View full report →
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Recon */}
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-blue-300">🔍 Recon</h4>
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
          <h4 className="text-xs font-semibold uppercase tracking-wide text-purple-300">🔬 Forensic</h4>
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
          <h4 className="text-xs font-semibold uppercase tracking-wide text-amber-300">🛡️ Response</h4>
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

const AGENT_ICONS: Record<string, string> = {
  recon: '🔍',
  forensic: '🧬',
  responder: '🛡️',
  report: '📋',
  completed: '✅',
  error: '❌',
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
          const icon = AGENT_ICONS[step.kind] ?? '⚡';
          return (
            <li key={i} className="flex items-start gap-2.5 px-3 py-2">
              <span className="shrink-0 text-base leading-none mt-0.5">{icon}</span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[11px] font-semibold text-slate-300">{step.agent}</span>
                  <span className="text-[10px] text-slate-600 font-mono">[{step.kind}]</span>
                </div>
                <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{step.summary}</p>
              </div>
              <span className="shrink-0 text-[9px] text-slate-600 font-mono mt-0.5">
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
        <span className="text-3xl">📋</span>
        <p className="mt-3 text-sm font-medium text-slate-300">No report yet</p>
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
            ↓ .md
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
                <>↓ PDF</>
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

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-0.5 text-sm text-slate-200">{value}</p>
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
