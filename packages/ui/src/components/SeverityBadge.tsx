import React from 'react';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md' | 'lg';
  showDot?: boolean;
  className?: string;
}

const SEVERITY_CONFIG: Record<string, { label: string; dot: string; badge: string }> = {
  critical: {
    label: 'Critical',
    dot: 'bg-red-500',
    badge: 'bg-red-500/20 text-red-400 border border-red-500/30',
  },
  high: {
    label: 'High',
    dot: 'bg-orange-500',
    badge: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  },
  medium: {
    label: 'Medium',
    dot: 'bg-yellow-500',
    badge: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  },
  low: {
    label: 'Low',
    dot: 'bg-blue-500',
    badge: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  },
  info: {
    label: 'Info',
    dot: 'bg-gray-400',
    badge: 'bg-gray-500/20 text-gray-400 border border-gray-500/30',
  },
  informational: {
    label: 'Info',
    dot: 'bg-gray-400',
    badge: 'bg-gray-500/20 text-gray-400 border border-gray-500/30',
  },
  unknown: {
    label: 'Unknown',
    dot: 'bg-gray-600',
    badge: 'bg-gray-600/20 text-gray-500 border border-gray-600/30',
  },
};

const SIZE_CONFIG = {
  sm: 'text-xs px-1.5 py-0.5',
  md: 'text-xs px-2 py-1',
  lg: 'text-sm px-2.5 py-1',
};

export function SeverityBadge({
  severity,
  size = 'md',
  showDot = true,
  className = '',
}: SeverityBadgeProps) {
  const key = severity.toLowerCase();
  const config = SEVERITY_CONFIG[key] ?? SEVERITY_CONFIG['unknown'];
  const sizeClass = SIZE_CONFIG[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium ${sizeClass} ${config.badge} ${className}`}
    >
      {showDot && <span className={`h-1.5 w-1.5 rounded-full ${config.dot}`} />}
      {config.label}
    </span>
  );
}
