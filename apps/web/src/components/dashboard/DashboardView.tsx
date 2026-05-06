'use client';

import useSWR from 'swr';
import { metricsApi, type DashboardMetrics } from '@/lib/api';
import { clsx } from 'clsx';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';
import { format } from 'date-fns';
import { LiveFeedPanel } from './LiveFeedPanel';

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
    { name: 'Endpoint Telemetry', count: 412, status: 'active' },
    { name: 'SIEM Events', count: 287, status: 'active' },
    { name: 'Cloud Audit', count: 198, status: 'active' },
    { name: 'Network Sensors', count: 243, status: 'active' },
    { name: 'Identity Provider', count: 107, status: 'active' },
  ],
  topMitre: [
    { tactic: 'Execution', count: 89 },
    { tactic: 'Defense Evasion', count: 67 },
    { tactic: 'Command & Control', count: 54 },
    { tactic: 'Credential Access', count: 43 },
    { tactic: 'Lateral Movement', count: 38 },
    { tactic: 'Exfiltration', count: 21 },
  ],
  alertsTrend: Array.from({ length: 24 }, (_, i) => ({
    timestamp: new Date(Date.now() - (23 - i) * 3600000).toISOString(),
    count: Math.floor(Math.random() * 80) + 20,
    severity: 'all',
  })),
  threatsBySource: [
    { source: 'Endpoint Telemetry', count: 412 },
    { source: 'SIEM Events', count: 287 },
    { source: 'Cloud Audit', count: 198 },
    { source: 'Network Sensors', count: 243 },
    { source: 'Identity Provider', count: 107 },
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

// ─── Main Dashboard ───────────────────────────────────────────────────────────

export function DashboardView() {
  const { data: metrics = MOCK_METRICS } = useSWR(
    'dashboard-metrics',
    () => metricsApi.getDashboard(),
    { fallbackData: MOCK_METRICS, refreshInterval: 60000 }
  );

  const trendData = metrics.alertsTrend.map((d) => ({
    time: format(new Date(d.timestamp), 'HH:mm'),
    count: d.count,
  }));

  const SEVERITY_CHART_DATA = [
    { name: 'Critical', value: metrics.alerts.critical, color: '#ef4444' },
    { name: 'High', value: metrics.alerts.high, color: '#f97316' },
    { name: 'Medium', value: metrics.alerts.medium, color: '#eab308' },
    { name: 'Low', value: metrics.alerts.low, color: '#3b82f6' },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Security Operations Center</h1>
          <p className="text-sm text-gray-500 mt-0.5">Overview of alerts, cases, and detection sources</p>
        </div>
      </div>

      {/* Top Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
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
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Alert trend */}
        <div className="col-span-2 bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-gray-300">Alert Volume (24h)</h3>
            <span className="text-xs text-gray-500">Last 24 hours</span>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={trendData}>
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
        </div>

        {/* Severity breakdown */}
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Severity Breakdown</h3>
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie data={SEVERITY_CHART_DATA} cx="50%" cy="50%" innerRadius={40} outerRadius={65} dataKey="value" strokeWidth={0}>
                {SEVERITY_CHART_DATA.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip formatter={(value, name) => [value, name]} contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: '8px', fontSize: '12px' }} />
            </PieChart>
          </ResponsiveContainer>
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

      {/* Bottom row */}
      <div className="grid grid-cols-3 gap-4">
        {/* MITRE ATT&CK */}
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Top MITRE ATT&CK Tactics</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={metrics.topMitre} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="tactic" tick={{ fill: '#9ca3af', fontSize: 10 }} tickLine={false} axisLine={false} width={100} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} name="Alerts" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Sources */}
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Alert Sources</h3>
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

        {/* Live Feed (realtime via WebSocket) */}
        <LiveFeedPanel />
      </div>
    </div>
  );
}
