import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { Card, CardHeader, CardBody, CardFooter } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';

const meta: Meta<typeof Card> = {
  title: 'Primitives/Card',
  component: Card,
  argTypes: {
    elevation: { control: 'select', options: ['flat', 'raised', 'inset'] },
    flush: { control: 'boolean' },
  },
};

export default meta;

type Story = StoryObj<typeof Card>;

export const Raised: Story = {
  args: { elevation: 'raised' },
  render: (args) => (
    <Card {...args} className="max-w-md">
      <CardHeader
        title="High-severity exfil response"
        description="Triggered on alert · isolated 12 hosts in the last 24h"
        action={<Badge tone="severity-high" dot>high</Badge>}
      />
      <CardBody>
        The playbook isolates the IAM role, snapshots the bucket policy and pages the on-call
        engineer. Auto-disabled on every run — re-enable in the editor after review.
      </CardBody>
      <CardFooter>
        <Button variant="ghost">Edit</Button>
        <Button variant="primary">Run</Button>
      </CardFooter>
    </Card>
  ),
};

export const Flat: Story = {
  args: { elevation: 'flat' },
  render: (args) => (
    <Card {...args} className="max-w-md">
      <CardHeader title="Connector status" />
      <CardBody>2 connectors are paused for credential rotation.</CardBody>
    </Card>
  ),
};

export const Inset: Story = {
  args: { elevation: 'inset' },
  render: (args) => (
    <Card {...args} className="max-w-md">
      <CardHeader title="Sandbox console" description="Replay events without touching production." />
      <CardBody>Inset surfaces signal that the content lives below the page surface.</CardBody>
    </Card>
  ),
};

export const Flush: Story = {
  args: { elevation: 'raised', flush: true },
  render: (args) => (
    <Card {...args} className="max-w-md">
      <table className="w-full text-xs">
        <thead className="border-b border-gray-800/60 text-left text-gray-500">
          <tr>
            <th className="p-3">Step</th>
            <th className="p-3">Status</th>
            <th className="p-3 text-right">Duration</th>
          </tr>
        </thead>
        <tbody>
          <tr className="border-b border-gray-900/60 text-gray-300">
            <td className="p-3">Enrich entity</td>
            <td className="p-3">Completed</td>
            <td className="p-3 text-right">1.2 s</td>
          </tr>
          <tr className="border-b border-gray-900/60 text-gray-300">
            <td className="p-3">Isolate host</td>
            <td className="p-3">Completed</td>
            <td className="p-3 text-right">3.4 s</td>
          </tr>
          <tr className="text-gray-300">
            <td className="p-3">Notify SOC</td>
            <td className="p-3">Running</td>
            <td className="p-3 text-right">—</td>
          </tr>
        </tbody>
      </table>
    </Card>
  ),
};

export const Grid: Story = {
  render: () => (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
      {Array.from({ length: 3 }).map((_, i) => (
        <Card key={i} elevation="raised">
          <CardHeader title={`Tile ${i + 1}`} description="42 events / hour" />
          <CardBody>Mean dwell time 6m 12s. Substrate calibration is current.</CardBody>
        </Card>
      ))}
    </div>
  ),
};
