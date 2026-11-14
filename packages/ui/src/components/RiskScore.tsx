import React from 'react';

interface RiskScoreProps {
  score: number; // 0-100
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

function getColor(score: number) {
  if (score >= 90) return { ring: 'text-red-500', bg: 'bg-red-500', label: 'Critical' };
  if (score >= 70) return { ring: 'text-orange-500', bg: 'bg-orange-500', label: 'High' };
  if (score >= 45) return { ring: 'text-yellow-500', bg: 'bg-yellow-500', label: 'Medium' };
  if (score >= 20) return { ring: 'text-blue-500', bg: 'bg-blue-500', label: 'Low' };
  return { ring: 'text-gray-500', bg: 'bg-gray-500', label: 'Minimal' };
}

const SIZE_CONFIG = {
  sm: { size: 'w-8 h-8', text: 'text-xs', bar: 'h-1' },
  md: { size: 'w-12 h-12', text: 'text-sm', bar: 'h-1.5' },
  lg: { size: 'w-16 h-16', text: 'text-base', bar: 'h-2' },
};

export function RiskScore({ score, size = 'md', showLabel = false, className = '' }: RiskScoreProps) {
  const s = Math.max(0, Math.min(100, score));
  const { ring, bg, label } = getColor(s);
  const { size: sizeClass, text: textClass, bar: barClass } = SIZE_CONFIG[size];

  return (
    <div className={`flex flex-col items-center gap-1 ${className}`}>
      {/* Circle */}
      <div
        className={`${sizeClass} rounded-full flex items-center justify-center font-bold ${ring} ring-2 ring-current bg-gray-900/60`}
      >
        <span className={`${textClass} tabular-nums`}>{s}</span>
      </div>

      {/* Bar */}
      <div className={`w-full bg-gray-700/50 rounded-full overflow-hidden ${barClass}`}>
        <div
          className={`h-full rounded-full transition-all ${bg}`}
          style={{ width: `${s}%` }}
        />
      </div>

      {showLabel && <span className={`text-xs font-medium ${ring}`}>{label}</span>}
    </div>
  );
}

interface RiskBarProps {
  score: number;
  className?: string;
}

export function RiskBar({ score, className = '' }: RiskBarProps) {
  const s = Math.max(0, Math.min(100, score));
  const { bg, label, ring } = getColor(s);

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className="flex-1 h-1.5 bg-gray-700/50 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${bg}`} style={{ width: `${s}%` }} />
      </div>
      <span className={`text-xs font-medium tabular-nums ${ring}`}>{s}</span>
      <span className="text-xs text-gray-500">{label}</span>
    </div>
  );
}
