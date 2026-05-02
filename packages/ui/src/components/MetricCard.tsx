import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  delta?: {
    value: number;
    label?: string;
    direction?: 'up' | 'down' | 'neutral';
  };
  icon?: React.ReactNode;
  color?: 'default' | 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'purple';
  loading?: boolean;
  className?: string;
}

const COLOR_CONFIG = {
  default: { icon: 'bg-gray-700/50 text-gray-300', border: 'border-gray-700/50' },
  red: { icon: 'bg-red-500/10 text-red-400', border: 'border-red-500/20' },
  orange: { icon: 'bg-orange-500/10 text-orange-400', border: 'border-orange-500/20' },
  yellow: { icon: 'bg-yellow-500/10 text-yellow-400', border: 'border-yellow-500/20' },
  green: { icon: 'bg-green-500/10 text-green-400', border: 'border-green-500/20' },
  blue: { icon: 'bg-blue-500/10 text-blue-400', border: 'border-blue-500/20' },
  purple: { icon: 'bg-purple-500/10 text-purple-400', border: 'border-purple-500/20' },
};

export function MetricCard({
  title,
  value,
  subtitle,
  delta,
  icon,
  color = 'default',
  loading = false,
  className = '',
}: MetricCardProps) {
  const config = COLOR_CONFIG[color];

  if (loading) {
    return (
      <div className={`rounded-xl border bg-gray-800/50 p-5 ${config.border} animate-pulse ${className}`}>
        <div className="h-4 w-24 bg-gray-700 rounded mb-3" />
        <div className="h-8 w-16 bg-gray-700 rounded mb-2" />
        <div className="h-3 w-20 bg-gray-700 rounded" />
      </div>
    );
  }

  return (
    <div className={`rounded-xl border bg-gray-800/50 p-5 ${config.border} ${className}`}>
      <div className="flex items-start justify-between gap-2">
        <p className="text-sm text-gray-400">{title}</p>
        {icon && (
          <div className={`rounded-lg p-2 ${config.icon}`}>
            <span className="text-lg">{icon}</span>
          </div>
        )}
      </div>

      <div className="mt-2">
        <span className="text-3xl font-bold text-white">
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>
      </div>

      {(subtitle || delta) && (
        <div className="mt-2 flex items-center gap-2">
          {subtitle && <p className="text-xs text-gray-500">{subtitle}</p>}
          {delta && (
            <span
              className={[
                'text-xs font-medium',
                delta.direction === 'up' ? 'text-red-400' : '',
                delta.direction === 'down' ? 'text-green-400' : '',
                delta.direction === 'neutral' ? 'text-gray-400' : '',
                !delta.direction ? 'text-gray-400' : '',
              ].join(' ')}
            >
              {delta.direction === 'up' ? '↑' : delta.direction === 'down' ? '↓' : ''}
              {Math.abs(delta.value)}%{delta.label ? ` ${delta.label}` : ''}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
