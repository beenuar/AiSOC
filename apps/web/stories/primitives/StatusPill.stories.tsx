import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { StatusPill } from '@/components/ui/StatusPill';

const meta: Meta<typeof StatusPill> = {
  title: 'Primitives/StatusPill',
  component: StatusPill,
  argTypes: {
    status: {
      control: 'select',
      options: ['pending', 'running', 'completed', 'failed', 'cancelled', 'unknown'],
    },
  },
  args: { status: 'running' },
};

export default meta;

type Story = StoryObj<typeof StatusPill>;

export const Running: Story = { args: { status: 'running' } };
export const Completed: Story = { args: { status: 'completed' } };
export const Failed: Story = { args: { status: 'failed' } };
export const Pending: Story = { args: { status: 'pending' } };
export const Cancelled: Story = { args: { status: 'cancelled' } };
export const Unknown: Story = { args: { status: 'unknown' } };

export const CustomLabel: Story = {
  args: { status: 'running', label: 'Isolating host (12 / 18)' },
};

export const Ladder: Story = {
  render: () => (
    <div className="flex flex-wrap gap-2">
      <StatusPill status="pending" />
      <StatusPill status="running" />
      <StatusPill status="completed" />
      <StatusPill status="failed" />
      <StatusPill status="cancelled" />
      <StatusPill status="unknown" />
    </div>
  ),
};
