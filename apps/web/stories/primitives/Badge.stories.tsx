import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { Badge } from '@/components/ui/Badge';

const meta: Meta<typeof Badge> = {
  title: 'Primitives/Badge',
  component: Badge,
  args: { children: 'phishing' },
  argTypes: {
    tone: {
      control: 'select',
      options: [
        'neutral',
        'info',
        'success',
        'warning',
        'danger',
        'severity-info',
        'severity-low',
        'severity-medium',
        'severity-high',
        'severity-critical',
      ],
    },
    dot: { control: 'boolean' },
  },
};

export default meta;

type Story = StoryObj<typeof Badge>;

export const Neutral: Story = { args: { tone: 'neutral' } };
export const Info: Story = { args: { tone: 'info', children: 'cloud-takeover' } };
export const Success: Story = { args: { tone: 'success', children: 'completed' } };
export const Warning: Story = { args: { tone: 'warning', children: 'flaky' } };
export const Danger: Story = { args: { tone: 'danger', children: 'failed' } };

export const SeverityLadder: Story = {
  render: () => (
    <div className="flex flex-wrap gap-2">
      <Badge tone="severity-info" dot>info</Badge>
      <Badge tone="severity-low" dot>low</Badge>
      <Badge tone="severity-medium" dot>medium</Badge>
      <Badge tone="severity-high" dot>high</Badge>
      <Badge tone="severity-critical" dot>critical</Badge>
    </div>
  ),
};

export const WithIcon: Story = {
  args: {
    tone: 'info',
    icon: <span aria-hidden="true">🛡</span>,
    children: 'connector: aws-cloudtrail',
  },
};

export const Matrix: Story = {
  render: () => (
    <div className="grid grid-cols-2 gap-3 text-xs">
      {(['neutral', 'info', 'success', 'warning', 'danger'] as const).map((t) => (
        <Badge key={t} tone={t}>{t}</Badge>
      ))}
    </div>
  ),
};
