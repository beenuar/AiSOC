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

import { useMemo, useState } from 'react';
import Link from 'next/link';
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
    assignee: 'sasha.lin@cyble.com',
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
              onClick={() => toast('Copilot will be wired up here.', { icon: '🤖' })}
              className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-200 transition-colors hover:bg-emerald-500/20"
            >
              Investigate with AI
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

      {/* Three-pane layout */}
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
