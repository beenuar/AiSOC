import React from 'react';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';

export interface AlertCardData {
  id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  source?: string;
  categories?: string[];
  mitre_tactics?: string[];
  created_at: string;
  event_count?: number;
  ai_summary?: string;
  assigned_to?: string;
}

interface AlertCardProps {
  alert: AlertCardData;
  onClick?: (alert: AlertCardData) => void;
  selected?: boolean;
  compact?: boolean;
  className?: string;
}

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function AlertCard({
  alert,
  onClick,
  selected = false,
  compact = false,
  className = '',
}: AlertCardProps) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onClick?.(alert)}
      onKeyDown={(e) => e.key === 'Enter' && onClick?.(alert)}
      className={[
        'rounded-lg border p-4 cursor-pointer transition-all',
        selected
          ? 'border-blue-500/60 bg-blue-500/10'
          : 'border-gray-700/50 bg-gray-800/50 hover:border-gray-600/60 hover:bg-gray-800/80',
        className,
      ].join(' ')}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-white truncate">{alert.title}</h3>
          {!compact && alert.description && (
            <p className="text-xs text-gray-400 mt-0.5 line-clamp-2">{alert.description}</p>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <SeverityBadge severity={alert.severity} size="sm" />
          <StatusBadge status={alert.status} size="sm" />
        </div>
      </div>

      {/* Metadata row */}
      {!compact && (
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-500">
          {alert.source && (
            <span className="flex items-center gap-1">
              <span className="text-gray-600">Source:</span>
              <span className="text-gray-400">{alert.source}</span>
            </span>
          )}
          {alert.event_count !== undefined && (
            <span className="flex items-center gap-1">
              <span className="text-gray-600">Events:</span>
              <span className="text-gray-400">{alert.event_count.toLocaleString()}</span>
            </span>
          )}
          <span className="ml-auto text-gray-600">{timeAgo(alert.created_at)}</span>
        </div>
      )}

      {/* MITRE tactics */}
      {!compact && alert.mitre_tactics && alert.mitre_tactics.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {alert.mitre_tactics.slice(0, 4).map((tactic) => (
            <span
              key={tactic}
              className="text-xs bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded px-1.5 py-0.5"
            >
              {tactic}
            </span>
          ))}
          {alert.mitre_tactics.length > 4 && (
            <span className="text-xs text-gray-600">+{alert.mitre_tactics.length - 4}</span>
          )}
        </div>
      )}

      {/* AI summary */}
      {!compact && alert.ai_summary && (
        <div className="mt-2 rounded bg-indigo-500/5 border border-indigo-500/10 px-2 py-1.5">
          <p className="text-xs text-indigo-300/80 line-clamp-2">{alert.ai_summary}</p>
        </div>
      )}
    </div>
  );
}
