import React from 'react';

export interface TimelineEventData {
  id: string;
  timestamp: string;
  type: 'alert' | 'action' | 'system' | 'user' | 'ai' | 'enrichment';
  title: string;
  description?: string;
  user?: string;
  severity?: string;
  metadata?: Record<string, string | number | boolean>;
}

interface TimelineEventProps {
  event: TimelineEventData;
  isLast?: boolean;
  className?: string;
}

const EVENT_TYPE_CONFIG = {
  alert: { dot: 'bg-red-500 ring-red-500/30', icon: '⚠', text: 'text-red-400' },
  action: { dot: 'bg-blue-500 ring-blue-500/30', icon: '⚡', text: 'text-blue-400' },
  system: { dot: 'bg-gray-500 ring-gray-500/30', icon: '⚙', text: 'text-gray-400' },
  user: { dot: 'bg-green-500 ring-green-500/30', icon: '👤', text: 'text-green-400' },
  ai: { dot: 'bg-purple-500 ring-purple-500/30', icon: '🤖', text: 'text-purple-400' },
  enrichment: { dot: 'bg-cyan-500 ring-cyan-500/30', icon: '🔍', text: 'text-cyan-400' },
};

function formatTime(ts: string) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDate(ts: string) {
  const d = new Date(ts);
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export function TimelineEvent({ event, isLast = false, className = '' }: TimelineEventProps) {
  const config = EVENT_TYPE_CONFIG[event.type] ?? EVENT_TYPE_CONFIG['system'];

  return (
    <div className={`flex gap-3 ${className}`}>
      {/* Dot + line */}
      <div className="flex flex-col items-center">
        <div className={`w-2.5 h-2.5 rounded-full ring-4 mt-1.5 flex-shrink-0 ${config.dot}`} />
        {!isLast && <div className="w-px flex-1 mt-1 bg-gray-700/50" />}
      </div>

      {/* Content */}
      <div className="flex-1 pb-5">
        <div className="flex items-baseline justify-between gap-2">
          <h4 className={`text-sm font-medium ${config.text}`}>{event.title}</h4>
          <div className="flex-shrink-0 text-right">
            <p className="text-xs text-gray-400">{formatTime(event.timestamp)}</p>
            <p className="text-xs text-gray-600">{formatDate(event.timestamp)}</p>
          </div>
        </div>

        {event.description && (
          <p className="mt-1 text-xs text-gray-400">{event.description}</p>
        )}

        {event.user && (
          <p className="mt-1 text-xs text-gray-500">by {event.user}</p>
        )}

        {event.metadata && Object.keys(event.metadata).length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {Object.entries(event.metadata).map(([k, v]) => (
              <span
                key={k}
                className="text-xs bg-gray-700/50 text-gray-400 rounded px-1.5 py-0.5"
              >
                {k}: {String(v)}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

interface TimelineProps {
  events: TimelineEventData[];
  className?: string;
}

export function Timeline({ events, className = '' }: TimelineProps) {
  return (
    <div className={`space-y-0 ${className}`}>
      {events.map((event, idx) => (
        <TimelineEvent
          key={event.id}
          event={event}
          isLast={idx === events.length - 1}
        />
      ))}
    </div>
  );
}
