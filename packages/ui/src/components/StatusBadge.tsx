import React from 'react';

export type AlertStatus =
  | 'new'
  | 'open'
  | 'in_progress'
  | 'pending_action'
  | 'resolved'
  | 'false_positive'
  | 'duplicate'
  | 'suppressed';

interface StatusBadgeProps {
  status: AlertStatus | string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const STATUS_CONFIG: Record<string, { label: string; badge: string }> = {
  new: { label: 'New', badge: 'bg-blue-500/20 text-blue-400 border border-blue-500/30' },
  open: { label: 'Open', badge: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' },
  in_progress: { label: 'In Progress', badge: 'bg-purple-500/20 text-purple-400 border border-purple-500/30' },
  pending_action: { label: 'Pending', badge: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' },
  resolved: { label: 'Resolved', badge: 'bg-green-500/20 text-green-400 border border-green-500/30' },
  false_positive: { label: 'False Positive', badge: 'bg-gray-500/20 text-gray-400 border border-gray-500/30' },
  duplicate: { label: 'Duplicate', badge: 'bg-gray-500/20 text-gray-400 border border-gray-500/30' },
  suppressed: { label: 'Suppressed', badge: 'bg-gray-600/20 text-gray-500 border border-gray-600/30' },
};

const SIZE_CONFIG = {
  sm: 'text-xs px-1.5 py-0.5',
  md: 'text-xs px-2 py-1',
  lg: 'text-sm px-2.5 py-1',
};

export function StatusBadge({ status, size = 'md', className = '' }: StatusBadgeProps) {
  const key = status.toLowerCase().replace(/ /g, '_');
  const config = STATUS_CONFIG[key] ?? { label: status, badge: 'bg-gray-500/20 text-gray-400 border border-gray-500/30' };
  const sizeClass = SIZE_CONFIG[size];

  return (
    <span className={`inline-flex items-center rounded-full font-medium ${sizeClass} ${config.badge} ${className}`}>
      {config.label}
    </span>
  );
}
