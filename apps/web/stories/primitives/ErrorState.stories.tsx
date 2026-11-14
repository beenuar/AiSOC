import type { Meta, StoryObj } from '@storybook/react-vite';
import { ErrorState } from '@/components/ui/ErrorState';

const meta: Meta<typeof ErrorState> = {
  title: 'Primitives/ErrorState',
  component: ErrorState,
  args: {
    title: 'Failed to load playbook runs',
    description: 'The runs service returned an error. The substrate path is still healthy.',
  },
};

export default meta;

type Story = StoryObj<typeof ErrorState>;

export const Basic: Story = {};

export const WithRetry: Story = {
  args: {
    onRetry: () => undefined,
    error: new Error('HTTP 503: runs-service circuit breaker open'),
  },
};

export const WithRawError: Story = {
  args: {
    title: 'Drafter call failed',
    description: 'The NL drafter returned a non-JSON payload. We fell back to the substrate.',
    error: 'SyntaxError: Unexpected token < in JSON at position 0',
  },
};
