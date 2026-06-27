import type { Meta, StoryObj } from '@storybook/react-vite';
import React from 'react';
import { Skeleton, SkeletonList, SkeletonCard } from '@/components/ui/Skeleton';

const meta: Meta<typeof Skeleton> = {
  title: 'Primitives/Skeleton',
  component: Skeleton,
};

export default meta;

type Story = StoryObj<typeof Skeleton>;

export const Single: Story = {
  render: () => <Skeleton className="h-10 w-64" />,
};

export const Rounded: Story = {
  render: () => (
    <div className="flex items-center gap-3">
      <Skeleton className="h-12 w-12" rounded="full" />
      <div className="space-y-2">
        <Skeleton className="h-3 w-40" />
        <Skeleton className="h-3 w-28" />
      </div>
    </div>
  ),
};

export const List: Story = {
  render: () => <SkeletonList count={6} />,
};

export const Cards: Story = {
  render: () => (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
      <SkeletonCard />
      <SkeletonCard />
      <SkeletonCard />
    </div>
  ),
};
