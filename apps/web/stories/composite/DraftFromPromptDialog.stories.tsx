import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { DraftFromPromptDialog } from '@/components/playbooks/DraftFromPromptDialog';

/**
 * Composite / DraftFromPromptDialog — T3.7 surface.
 *
 * The story stubs `fetch` and `next/navigation` so the dialog renders
 * its happy path without a backend. Hit "Draft playbook" to see the
 * confirmation flow.
 *
 * Originally part of the T3.8 design-system PR (#331) but split out
 * because the component lived on the T3.7 branch (#330). Re-added
 * after both T-IDs landed on `main` (2026-06-27).
 */

const meta: Meta<typeof DraftFromPromptDialog> = {
  title: 'Composite/DraftFromPromptDialog',
  component: DraftFromPromptDialog,
  parameters: {
    docs: {
      description: {
        component:
          'NL → playbook drafter modal (T3.7). Posts to /api/v1/playbooks/draft-from-nl and routes to /playbooks/new with the draft parked in sessionStorage. In Storybook the network is stubbed to a deterministic success payload.',
      },
    },
  },
  decorators: [
    (Story) => {
      // Stub fetch and the next-navigation router so the story stays
      // hermetic. The decorator only runs once per story render.
      if (typeof window !== 'undefined') {
        window.fetch = async () =>
          ({
            ok: true,
            status: 200,
            text: async () => 'ok',
            json: async () => ({
              playbook: {
                id: 'demo-draft',
                name: 'Demo NL draft',
                description: 'Storybook demo prompt',
                version: '1.0.0',
                tags: ['nl-drafted', 'draft'],
                trigger: { on: 'alert', severity: ['high'] },
                steps: [],
                author: 'AiSOC',
                enabled: false,
                created_at: '2026-06-27T00:00:00Z',
                updated_at: '2026-06-27T00:00:00Z',
              },
              rationale: 'demo',
              used_llm: false,
              schema_validated: true,
            }),
          }) as unknown as Response;
      }
      return <Story />;
    },
  ],
};

export default meta;

type Story = StoryObj<typeof DraftFromPromptDialog>;

export const Open: Story = {
  args: {
    open: true,
    onClose: () => undefined,
  },
};

export const Closed: Story = {
  args: {
    open: false,
    onClose: () => undefined,
  },
};
