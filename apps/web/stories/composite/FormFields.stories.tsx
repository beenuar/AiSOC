import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { Button } from '@/components/ui/Button';

/**
 * Composite / FormFields — the canonical form patterns the console
 * uses. Inputs, textareas and selects all share the same dark surface
 * + blue-focus combo so screens feel cohesive.
 */

const meta: Meta = {
  title: 'Composite/FormFields',
};

export default meta;

type Story = StoryObj;

const inputCls =
  'mt-1 w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-sm text-gray-200 placeholder:text-gray-600 focus:border-blue-600 focus:outline-none focus:ring-1 focus:ring-blue-600';

export const TextInput: Story = {
  render: () => (
    <label className="block max-w-sm text-xs text-gray-400">
      Playbook name
      <input className={inputCls} placeholder="e.g. High-sev exfil response" />
    </label>
  ),
};

export const DisabledInput: Story = {
  render: () => (
    <label className="block max-w-sm text-xs text-gray-400">
      ID (auto-generated)
      <input className={inputCls} value="exfil-response-2026" readOnly disabled />
    </label>
  ),
};

export const Textarea: Story = {
  render: () => (
    <label className="block max-w-2xl text-xs text-gray-400">
      Description
      <textarea
        rows={4}
        className={inputCls}
        placeholder="Describe what this playbook responds to and why."
      />
    </label>
  ),
};

export const Select: Story = {
  render: () => (
    <label className="block max-w-sm text-xs text-gray-400">
      Trigger on
      <select className={inputCls}>
        <option>alert</option>
        <option>case</option>
        <option>schedule</option>
        <option>manual</option>
        <option>webhook</option>
      </select>
    </label>
  ),
};

export const Submit: Story = {
  render: () => (
    <form className="max-w-md space-y-3">
      <label className="block text-xs text-gray-400">
        Prompt
        <textarea rows={5} className={inputCls} defaultValue="Isolate the host and notify the SOC" />
      </label>
      <div className="flex items-center justify-end gap-2">
        <Button variant="outline" size="sm">Cancel</Button>
        <Button variant="primary" size="sm">Draft playbook</Button>
      </div>
    </form>
  ),
};
