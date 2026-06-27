import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { Button } from '@/components/ui/Button';

/**
 * Composite / Banners — informational, warning and danger banners
 * shown across the console. Local components for now; these will
 * graduate to ui/Banner when their consumers are converted.
 */

const meta: Meta = {
  title: 'Composite/Banners',
};

export default meta;

type Story = StoryObj;

function Banner({
  tone,
  title,
  description,
  action,
}: {
  tone: 'info' | 'warning' | 'danger' | 'success';
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  const palette: Record<typeof tone, string> = {
    info: 'border-blue-500/40 bg-blue-500/10 text-blue-200',
    warning: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
    danger: 'border-red-500/40 bg-red-500/10 text-red-200',
    success: 'border-green-500/40 bg-green-500/10 text-green-200',
  };
  return (
    <div className={`flex items-start justify-between gap-4 rounded-xl border px-4 py-3 ${palette[tone]}`}>
      <div>
        <div className="text-sm font-semibold">{title}</div>
        <p className="mt-0.5 text-xs opacity-90">{description}</p>
      </div>
      {action}
    </div>
  );
}

export const Info: Story = {
  render: () => (
    <Banner
      tone="info"
      title="Drafted from a prompt"
      description="Review each step before saving. This playbook ships with `enabled: false`."
      action={<Button variant="ghost" size="sm">Got it</Button>}
    />
  ),
};

export const Warning: Story = {
  render: () => (
    <Banner
      tone="warning"
      title="Substrate fallback in use"
      description="The configured LLM provider is unreachable. The deterministic substrate is producing drafts."
    />
  ),
};

export const Danger: Story = {
  render: () => (
    <Banner
      tone="danger"
      title="Destructive step requires approval"
      description="Step 'Block IP' will be executed against production firewalls. Approve to proceed."
      action={<Button variant="destructive" size="sm">Approve</Button>}
    />
  ),
};

export const Success: Story = {
  render: () => (
    <Banner
      tone="success"
      title="Playbook saved"
      description="Enable the playbook from the gallery once peer-review is complete."
    />
  ),
};
