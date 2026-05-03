import { clsx } from 'clsx';
import type { HTMLAttributes } from 'react';

interface SkeletonProps extends HTMLAttributes<HTMLDivElement> {
  rounded?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
}

/**
 * A bg-pulsing block used as a placeholder while data loads.
 *
 * Prefer this over silently rendering empty space — it gives the UI a
 * predictable shape so layout doesn't jump when real data arrives.
 */
export function Skeleton({ className, rounded = 'md', ...props }: SkeletonProps) {
  const roundedClass = {
    sm: 'rounded-sm',
    md: 'rounded-md',
    lg: 'rounded-lg',
    xl: 'rounded-xl',
    full: 'rounded-full',
  }[rounded];

  return (
    <div
      className={clsx(
        'animate-pulse bg-gradient-to-r from-gray-800/40 via-gray-700/40 to-gray-800/40 bg-[length:200%_100%]',
        roundedClass,
        className,
      )}
      style={{ animation: 'skeleton-shimmer 1.4s ease-in-out infinite' }}
      {...props}
    />
  );
}

interface SkeletonListProps {
  count?: number;
  className?: string;
  rowClassName?: string;
}

export function SkeletonList({ count = 5, className, rowClassName }: SkeletonListProps) {
  return (
    <div className={clsx('space-y-3', className)}>
      {Array.from({ length: count }).map((_, i) => (
        <Skeleton key={i} className={clsx('h-14 w-full', rowClassName)} />
      ))}
    </div>
  );
}

export function SkeletonCard() {
  return (
    <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-5 space-y-4">
      <Skeleton className="h-4 w-1/3" />
      <Skeleton className="h-8 w-2/3" />
      <Skeleton className="h-3 w-full" />
      <Skeleton className="h-3 w-4/5" />
    </div>
  );
}
