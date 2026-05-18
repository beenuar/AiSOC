'use client';

/**
 * DashboardView
 * =============
 * Main SOC dashboard with live metrics, charts, and source activity.
 *
 * WS-F3: Drag-and-drop widget reordering.
 * Each major section (DashboardWelcome, Top Metrics, Charts row, Bottom row,
 * SOC Performance) is a draggable "widget". The user can grab the ⠿ handle in
 * the widget's header and drop it anywhere in the layout. Order is persisted to
 * localStorage so it survives page refreshes.
 *
 * Author: Beenu <beenu@cyble.com>
 */

import React, { Component, Suspense, type ErrorInfo, type ReactNode, useState, useEffect, useRef, useCallback } from 'react';
import useSWR from 'swr';
import { metricsApi, type DashboardMetrics } from '@/lib/api';
import { clsx } from 'clsx';
import dynamic from 'next/dynamic';
import { format } from 'date-fns';
import { LiveFeedPanel } from './LiveFeedPanel';
import { SOCMetricsDashboard } from './SOCMetricsDashboard';
import { DashboardWelcome } from './DashboardWelcome';
import { FunnelKpiBar } from './FunnelKpiBar';
import { EfficiencyReport } from './EfficiencyReport';
import { PipelineHealth } from './PipelineHealth';

const RechartsArea = dynamic(
  () => import('recharts').then((m) => {
    const { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } = m;
    function RechartsAreaInner(props: { data: { time: string; count: number }[] }) {
      return (
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={props.data}>
            <defs>
              <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
            <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} interval={3} />
            <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
            <Tooltip content={<CustomTooltip />} />
            <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="url(#alertGrad)" strokeWidth={2} name="Alerts" />
          </AreaChart>
        </ResponsiveContainer>
      );
    }
    return RechartsAreaInner;
  }),
  { ssr: false, loading: () => <div className="h-[180px] bg-gray-800/30 animate-pulse rounded" /> },
);

const RechartsPie = dynamic(
  () => import('recharts').then((m) => {
    const { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } = m;
    function RechartsPieInner(props: { data: { name: string; value: number; color: string }[] }) {
      return (
        <ResponsiveContainer width="100%" height={140}>
          <PieChart>
            <Pie data={props.data} cx="50%" cy="50%" innerRadius={40} outerRadius={65} dataKey="value" strokeWidth={0}>
              {props.data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip formatter={(value, name) => [value, name]} contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: '8px', fontSize: '12px' }} />
          </PieChart>
        </ResponsiveContainer>
      );
    }
    return RechartsPieInner;
  }),
  { ssr: false, loading: () => <div className="h-[140px] bg-gray-800/30 animate-pulse rounded" /> },
);

const RechartsBar = dynamic(
  () => import('recharts').then((m) => {
    const { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } = m;
    function RechartsBarInner(props: { data: { tactic: string; count: number }[] }) {
      return (
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={props.data} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
            <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
            <YAxis type="category" dataKey="tactic" tick={{ fill: '#9ca3af', fontSize: 10 }} tickLine={false} axisLine={false} width={100} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} name="Alerts" />
          </BarChart>
        </ResponsiveContainer>
      );
    }
    return RechartsBarInner;
  }),
  { ssr: false, loading: () => <div className="h-[180px] bg-gray-800/30 animate-pulse rounded" /> },
);

class DashboardErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  state = { hasError: false };
  static getDerivedStateFromError() { return { hasError: true }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('[DashboardView] render error:', error, info); }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-6 text-center text-gray-400">
          <p className="text-sm">Dashboard encountered an error. Please refresh.</p>
          <button onClick={() => this.setState({ hasError: false })} className="mt-2 text-xs text-blue-400 underline">Retry</button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_METRICS: DashboardMetrics = {
  alerts: {
    total: 1247,
    new: 89,
    critical: 12,
    high: 43,
    medium: 156,
    low: 289,
    resolvedToday: 67,
    mttr: 42,
  },
  cases: {
    open: 23,
    inProgress: 15,
    resolvedThisWeek: 34,
  },
  sources: [
    { name: 'CrowdStrike EDR', count: 412, status: 'active' },
    { name: 'Microsoft Sentinel', count: 287, status: 'active' },
    { name: 'AWS CloudTrail', count: 198, status: 'active' },
    { name: 'Okta Identity', count: 163, status: 'active' },
    { name: 'Google Workspace', count: 107, status: 'active' },
    { name: 'GitHub Audit', count: 84, status: 'active' },
  ],
  topMitre: [
    { tactic: 'Execution', count: 89 },
    { tactic: 'Defense Evasion', count: 67 },
    { tactic: 'Command & Control', count: 54 },
    { tactic: 'Credential Access', count: 43 },
    { tactic: 'Lateral Movement', count: 38 },
    { tactic: 'Exfiltration', count: 21 },
  ],
  // Deterministic timestamps — no Date.now()/Math.random() to avoid SSR hydration mismatches.
  alertsTrend: Array.from({ length: 24 }, (_, i) => ({
    timestamp: new Date(new Date('2026-05-06T12:00:00Z').getTime() - (23 - i) * 3600000).toISOString(),
    count: ((i * 37 + 13) % 80) + 20,
    severity: 'all',
  })),
  threatsBySource: [
    { source: 'CrowdStrike EDR', count: 412 },
    { source: 'Microsoft Sentinel', count: 287 },
    { source: 'AWS CloudTrail', count: 198 },
    { source: 'Okta Identity', count: 163 },
    { source: 'Google Workspace', count: 107 },
    { source: 'GitHub Audit', count: 84 },
  ],
};

// ─── Metric Card ──────────────────────────────────────────────────────────────

interface MetricCardProps {
  label: string;
  value: string | number;
  sub?: string;
  color?: 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'purple' | 'gray';
  trend?: { value: number; label: string };
}

const COLOR_MAP = {
  red: 'text-red-400',
  orange: 'text-orange-400',
  yellow: 'text-yellow-400',
  green: 'text-green-400',
  blue: 'text-blue-400',
  purple: 'text-purple-400',
  gray: 'text-gray-400',
};

function MetricCard({ label, value, sub, color = 'blue', trend }: MetricCardProps) {
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
      <div>
        <p className="text-xs text-gray-500 font-medium uppercase tracking-wider mb-2">{label}</p>
        <p className={clsx('text-3xl font-bold', COLOR_MAP[color])}>{value}</p>
        {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
      </div>
      {trend && (
        <div className={clsx(
          'flex items-center gap-1 mt-3 text-xs',
          trend.value >= 0 ? 'text-red-400' : 'text-green-400'
        )}>
          <span>{trend.value >= 0 ? '+' : '-'}{Math.abs(trend.value)}%</span>
          <span className="text-gray-600">{trend.label}</span>
        </div>
      )}
    </div>
  );
}

// ─── Chart tooltip ────────────────────────────────────────────────────────────

function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs">
      <p className="text-gray-400 mb-1">{label}</p>
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ color: p.color }} className="font-medium">
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
}

// ─── Drag-and-Drop Widget Layout (WS-F3) ──────────────────────────────────────

const WIDGET_ORDER_KEY = 'aisoc:dashboard:widget-order';

type WidgetId =
  | 'welcome'
  | 'funnel-kpis'
  | 'efficiency-and-pipeline'
  | 'top-metrics'
  | 'charts-row'
  | 'bottom-row'
  | 'soc-performance';

const DEFAULT_WIDGET_ORDER: WidgetId[] = [
  'welcome',
  'funnel-kpis',
  'efficiency-and-pipeline',
  'top-metrics',
  'charts-row',
  'bottom-row',
  'soc-performance',
];

function loadWidgetOrder(): WidgetId[] {
  if (typeof window === 'undefined') return DEFAULT_WIDGET_ORDER;
  try {
    const raw = localStorage.getItem(WIDGET_ORDER_KEY);
    if (!raw) return DEFAULT_WIDGET_ORDER;
    const parsed = JSON.parse(raw) as WidgetId[];
    // Guard against stale storage with missing or extra IDs
    if (
      Array.isArray(parsed) &&
      parsed.length === DEFAULT_WIDGET_ORDER.length &&
      DEFAULT_WIDGET_ORDER.every((id) => parsed.includes(id))
    ) {
      return parsed;
    }
  } catch {}
  return DEFAULT_WIDGET_ORDER;
}

/** Drag state kept in a ref so re-renders stay minimal during the drag gesture. */
interface DragState {
  dragId: WidgetId | null;
  overId: WidgetId | null;
}

interface DraggableWidgetProps {
  id: WidgetId;
  dragState: DragState;
  onDragStart: (id: WidgetId) => void;
  onDragOver: (id: WidgetId) => void;
  onDrop: () => void;
  children: ReactNode;
}

/**
 * Thin drag-and-drop shell around each dashboard section.
 * The ⠿ handle (aria-label "Drag to reorder") is the only interactive target;
 * clicking anywhere else in the widget works normally.
 */
function DraggableWidget({ id, dragState, onDragStart, onDragOver, onDrop, children }: DraggableWidgetProps) {
  const isDragging = dragState.dragId === id;
  const isOver = dragState.overId === id && dragState.dragId !== id;

  return (
    <div
      draggable
      onDragStart={() => onDragStart(id)}
      onDragOver={(e) => { e.preventDefault(); onDragOver(id); }}
      onDrop={(e) => { e.preventDefault(); onDrop(); }}
      onDragEnd={onDrop}
      className={clsx(
        'relative group transition-opacity',
        isDragging && 'opacity-40',
        isOver && 'ring-2 ring-blue-500/60 ring-offset-2 ring-offset-gray-950 rounded-xl',
      )}
      aria-label={`Dashboard widget: ${id}`}
    >
      {/* Drag handle — visible on hover */}
      <button
        aria-label="Drag to reorder"
        title="Drag to reorder"
        className={clsx(
          'absolute top-2 right-2 z-10 cursor-grab active:cursor-grabbing',
          'px-1.5 py-0.5 rounded text-gray-600 hover:text-gray-400',
          'opacity-0 group-hover:opacity-100 transition-opacity',
          'select-none text-base leading-none',
        )}
        // Pointer-down on the handle initiates the native drag
        onPointerDown={(e) => {
          // We rely on the parent div's draggable; just prevent focus loss
          e.currentTarget.closest('[draggable]')?.dispatchEvent(
            new DragEvent('dragstart', { bubbles: true })
          );
        }}
        tabIndex={-1}
      >
        ⠿
      </button>
      {children}
    </div>
  );
}

/** Persist + manage the ordered list of widget IDs. */
function useDashboardLayout() {
  const [order, setOrder] = useState<WidgetId[]>(DEFAULT_WIDGET_ORDER);
  const dragState = useRef<DragState>({ dragId: null, overId: null });
  // Trigger a render when drag state changes so highlights update
  const [, forceRender] = useState(0);

  // Hydrate from localStorage on mount (client-only)
  useEffect(() => { setOrder(loadWidgetOrder()); }, []);

  const handleDragStart = useCallback((id: WidgetId) => {
    dragState.current = { dragId: id, overId: null };
    forceRender((n) => n + 1);
  }, []);

  const handleDragOver = useCallback((id: WidgetId) => {
    if (dragState.current.overId !== id) {
      dragState.current = { ...dragState.current, overId: id };
      forceRender((n) => n + 1);
    }
  }, []);

  const handleDrop = useCallback(() => {
    const { dragId, overId } = dragState.current;
    dragState.current = { dragId: null, overId: null };
    forceRender((n) => n + 1);

    if (!dragId || !overId || dragId === overId) return;

    setOrder((prev) => {
      const next = [...prev];
      const from = next.indexOf(dragId);
      const to = next.indexOf(overId);
      if (from === -1 || to === -1) return prev;
      next.splice(from, 1);
      next.splice(to, 0, dragId);
      try { localStorage.setItem(WIDGET_ORDER_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);

  return { order, dragState: dragState.current, handleDragStart, handleDragOver, handleDrop };
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export function DashboardView() {
  const { data: rawMetrics } = useSWR(
    'dashboard-metrics',
    () => metricsApi.getDashboard(),
    {
      fallbackData: MOCK_METRICS,
      refreshInterval: 60000,
      shouldRetryOnError: false,
      errorRetryCount: 0,
      revalidateOnFocus: false,
    }
  );

  // Hybrid: prefer real API fields when present, fall back to mock for missing
  // sections (e.g. /metrics/dashboard currently returns alertsTrend: [] and no
  // threatsBySource yet, so the charts would render empty without this merge).
  const apiData = rawMetrics as Partial<DashboardMetrics> | undefined;
  const hasRealAlerts = !!apiData && typeof apiData.alerts?.total === 'number';
  const metrics: DashboardMetrics = hasRealAlerts
    ? {
        alerts: apiData!.alerts as DashboardMetrics['alerts'],
        cases: apiData!.cases ?? MOCK_METRICS.cases,
        sources:
          Array.isArray(apiData!.sources) && apiData!.sources!.length
            ? apiData!.sources!
            : MOCK_METRICS.sources,
        topMitre:
          Array.isArray(apiData!.topMitre) && apiData!.topMitre!.length
            ? apiData!.topMitre!
            : MOCK_METRICS.topMitre,
        alertsTrend:
          Array.isArray(apiData!.alertsTrend) && apiData!.alertsTrend!.length
            ? apiData!.alertsTrend!
            : MOCK_METRICS.alertsTrend,
        threatsBySource:
          Array.isArray(apiData!.threatsBySource) && apiData!.threatsBySource!.length
            ? apiData!.threatsBySource!
            : MOCK_METRICS.threatsBySource,
      }
    : MOCK_METRICS;

  const trendData = metrics.alertsTrend.map((d) => ({
    time: format(new Date(d.timestamp), 'HH:mm'),
    count: d.count,
  }));

  const SEVERITY_CHART_DATA = [
    { name: 'Critical', value: metrics.alerts.critical, color: '#ef4444' },
    { name: 'High', value: metrics.alerts.high, color: '#f97316' },
    { name: 'Medium', value: metrics.alerts.medium, color: '#eab308' },
    { name: 'Low', value: metrics.alerts.low, color: '#3b82f6' },
    { name: 'Info', value: metrics.alerts.info ?? 0, color: '#64748b' },
  ];

  // WS-F3: drag-and-drop widget reordering
  const { order, dragState, handleDragStart, handleDragOver, handleDrop } = useDashboardLayout();

  /** Map each widget ID to its rendered section. */
  const widgetContent: Record<WidgetId, ReactNode> = {
    welcome: <Suspense fallback={null}><DashboardWelcome /></Suspense>,

    // PR-3 / W1: Six-tile funnel KPI strip (events → correlations → alerts +
    // signal/noise, MTTD, analyst queue) backed by /api/v1/metrics/funnel.
    'funnel-kpis': <FunnelKpiBar period="24h" />,

    // PR-3 / W1+W9: Efficiency ratios (correlation efficiency, alert yield,
    // MITRE coverage) alongside per-stage pipeline health.
    'efficiency-and-pipeline': (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <EfficiencyReport period="24h" />
        <PipelineHealth />
      </div>
    ),

    'top-metrics': (
      <div>
        {/* Section header */}
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-semibold text-gray-100">Security Operations Center</h2>
            <p className="text-sm text-gray-500 mt-0.5">
              Entity-risk alerting, confidence-scored triage, and{' '}
              {metrics.sources.filter((s) => s.status === 'active').length} connected sources
            </p>
          </div>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          <MetricCard
            label="Active Alerts"
            value={metrics.alerts.total}
            sub={`${metrics.alerts.new} new today`}
            color="blue"
            trend={{ value: 12, label: 'vs yesterday' }}
          />
          <MetricCard
            label="Critical"
            value={metrics.alerts.critical}
            sub="Require immediate action"
            color="red"
            trend={{ value: -3, label: 'vs yesterday' }}
          />
          <MetricCard
            label="Open Cases"
            value={metrics.cases.open}
            sub={`${metrics.cases.inProgress} in progress`}
            color="orange"
          />
          <MetricCard
            label="MTTR"
            value={`${metrics.alerts.mttr}m`}
            sub="Mean time to resolve"
            color="green"
            trend={{ value: -8, label: 'vs last week' }}
          />
          <MetricCard
            label="Connected Sources"
            value={metrics.sources.filter(s => s.status === 'active').length}
            sub="EDR, SIEM, Cloud, IAM, SaaS"
            color="purple"
          />
        </div>
      </div>
    ),

    'charts-row': (
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-300">Alert Volume (24h)</h3>
            <span className="text-xs text-gray-500">Last 24 hours</span>
          </div>
          <RechartsArea data={trendData} />
        </div>
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Severity Breakdown</h3>
          <RechartsPie data={SEVERITY_CHART_DATA} />
          <div className="space-y-1.5 mt-2">
            {SEVERITY_CHART_DATA.map((d) => (
              <div key={d.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                  <span className="text-gray-400">{d.name}</span>
                </div>
                <span className="text-gray-300 font-medium">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    ),

    'bottom-row': (
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Top MITRE ATT&CK Tactics</h3>
          <RechartsBar data={metrics.topMitre} />
        </div>
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Connected Sources</h3>
          <div className="space-y-3">
            {metrics.sources.map((src) => {
              const maxCount = Math.max(...metrics.sources.map(s => s.count));
              const pct = Math.round((src.count / maxCount) * 100);
              return (
                <div key={src.name}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className={clsx(
                        'w-1.5 h-1.5 rounded-full',
                        src.status === 'active' ? 'bg-green-500' : 'bg-gray-500'
                      )} />
                      <span className="text-xs text-gray-300">{src.name}</span>
                    </div>
                    <span className="text-xs text-gray-500">{src.count}</span>
                  </div>
                  <div className="h-1 bg-gray-800 rounded-full">
                    <div className="h-1 bg-blue-500/60 rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
        <LiveFeedPanel />
      </div>
    ),

    'soc-performance': (
      <div className="pt-2">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-base font-semibold text-gray-100">SOC Performance</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Outcome metrics, agent calibration, and technique coverage. Auto-computed every 30s.
            </p>
          </div>
        </div>
        <SOCMetricsDashboard />
      </div>
    ),
  };

  return (
    <DashboardErrorBoundary>
      <div className="space-y-5">
        {order.map((id) => (
          <DraggableWidget
            key={id}
            id={id}
            dragState={dragState}
            onDragStart={handleDragStart}
            onDragOver={handleDragOver}
            onDrop={handleDrop}
          >
            {widgetContent[id]}
          </DraggableWidget>
        ))}
      </div>
    </DashboardErrorBoundary>
  );
}
