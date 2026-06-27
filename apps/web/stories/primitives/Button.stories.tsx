import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { Button } from '@/components/ui/Button';

const meta: Meta<typeof Button> = {
  title: 'Primitives/Button',
  component: Button,
  args: {
    children: 'Run playbook',
  },
  argTypes: {
    variant: { control: 'select', options: ['primary', 'secondary', 'destructive', 'ghost', 'outline'] },
    size: { control: 'select', options: ['xs', 'sm', 'md', 'lg'] },
    loading: { control: 'boolean' },
    disabled: { control: 'boolean' },
    pressed: { control: 'boolean' },
  },
  parameters: {
    docs: {
      description: {
        component:
          'AiSOC console button. Five variants × four sizes — the only button you should reach for in new code.',
      },
    },
  },
};

export default meta;

type Story = StoryObj<typeof Button>;

export const Primary: Story = {
  args: { variant: 'primary' },
};

export const Secondary: Story = {
  args: { variant: 'secondary', children: 'Cancel' },
};

export const Destructive: Story = {
  args: { variant: 'destructive', children: 'Block IP' },
};

export const Ghost: Story = {
  args: { variant: 'ghost', children: 'Skip step' },
};

export const Outline: Story = {
  args: { variant: 'outline', children: 'View details' },
};

export const AllSizes: Story = {
  render: () => (
    <div className="flex items-center gap-3">
      <Button size="xs">XS</Button>
      <Button size="sm">SM</Button>
      <Button size="md">MD</Button>
      <Button size="lg">LG</Button>
    </div>
  ),
};

export const WithLeadingIcon: Story = {
  args: {
    variant: 'primary',
    children: 'Draft playbook',
    leadingIcon: <span aria-hidden="true">✨</span>,
  },
};

export const Loading: Story = {
  args: { variant: 'primary', loading: true, children: 'Drafting…' },
};

export const Disabled: Story = {
  args: { variant: 'primary', disabled: true, children: 'Not available' },
};

export const Pressed: Story = {
  args: { variant: 'outline', pressed: true, children: 'Filters on' },
};

export const Matrix: Story = {
  render: () => (
    <div className="space-y-4">
      {(['primary', 'secondary', 'destructive', 'ghost', 'outline'] as const).map((v) => (
        <div key={v} className="flex items-center gap-3">
          <div className="w-24 font-mono text-[10px] uppercase text-gray-500">{v}</div>
          {(['xs', 'sm', 'md', 'lg'] as const).map((s) => (
            <Button key={s} variant={v} size={s}>
              {v}
            </Button>
          ))}
        </div>
      ))}
    </div>
  ),
};
