import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';

/**
 * Composite / KPI Tiles — the dashboard's atomic tile. Wraps a Card,
 * surfaces a single metric with a comparison delta, and lets the
 * marketing team grab high-fidelity screenshots without spinning up
 * the live backend.
 */

const meta: Meta = {
  title: 'Composite/KPI Tiles',
};

export default meta;

type Story = StoryObj;

function KpiTile({
  label,
  value,
  delta,
  hint,
  tone,
}: {
  label: string;
  value: string;
  delta?: { value: string; direction: 'up' | 'down' };
  hint?: string;
  tone?: 'info' | 'success' | 'warning' | 'danger';
}) {
  const deltaColor =
    delta?.direction === 'up' ? 'text-green-400' : delta?.direction === 'down' ? 'text-red-400' : 'text-gray-400';
  return (
    <Card elevation="raised" className="min-w-[220px]">
      <div className="flex items-start justify-between">
        <div className="text-[11px] uppercase tracking-wide text-gray-500">{label}</div>
        {tone && <Badge tone={tone}>{tone}</Badge>}
      </div>
      <div className="mt-2 text-2xl font-semibold text-gray-100">{value}</div>
      {delta && (
        <div className={`mt-1 text-xs ${deltaColor}`}>
          {delta.direction === 'up' ? '▲' : '▼'} {delta.value}
        </div>
      )}
      {hint && <div className="mt-2 text-xs text-gray-500">{hint}</div>}
    </Card>
  );
}

export const SingleTile: Story = {
  render: () => (
    <KpiTile
      label="Alerts triaged (24h)"
      value="1,284"
      delta={{ value: '12.4 % vs. yesterday', direction: 'up' }}
      hint="Substrate path handled 71 %; LLM path handled 29 %."
      tone="success"
    />
  ),
};

export const Row: Story = {
  render: () => (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      <KpiTile
        label="Mean dwell time"
        value="6 m 12 s"
        delta={{ value: '8 s faster', direction: 'down' }}
        tone="success"
      />
      <KpiTile
        label="High-sev open"
        value="42"
        delta={{ value: '3 new since 09:00', direction: 'up' }}
        tone="warning"
      />
      <KpiTile label="Auto-isolations" value="18" delta={{ value: '4 today', direction: 'up' }} tone="info" />
      <KpiTile
        label="Playbooks enabled"
        value="73 / 91"
        hint="18 disabled drafts pending review."
        tone="info"
      />
    </div>
  ),
};
