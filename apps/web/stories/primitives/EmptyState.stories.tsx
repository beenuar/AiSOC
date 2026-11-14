import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { EmptyState } from '@/components/ui/EmptyState';
import { Button } from '@/components/ui/Button';

const meta: Meta<typeof EmptyState> = {
  title: 'Primitives/EmptyState',
  component: EmptyState,
  argTypes: {
    variant: { control: 'select', options: ['default', 'planned-v1.1'] },
  },
  args: {
    title: 'No playbooks yet',
    description:
      'Drafted playbooks land here. Use ✨ Draft from prompt to bootstrap your first one from a sentence.',
  },
};

export default meta;

type Story = StoryObj<typeof EmptyState>;

export const Default: Story = {
  args: {
    variant: 'default',
    icon: <span aria-hidden="true">📒</span>,
    action: <Button variant="primary">Draft from prompt</Button>,
  },
};

export const NoAction: Story = {
  args: {
    variant: 'default',
    title: 'No runs in the selected window',
    description: 'Run history is scoped to the last 24 hours by default.',
  },
};

export const Planned: Story = {
  args: {
    variant: 'planned-v1.1',
    title: 'Behavioural baselines',
    description: 'UEBA baselines per-user, per-host, per-asset class — coming in v1.1.',
    icon: <span aria-hidden="true">🧪</span>,
  },
};
