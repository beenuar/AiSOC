import React from 'react';

interface MitreBadgeProps {
  tactic?: string;
  technique?: string;
  techniqueId?: string;
  size?: 'sm' | 'md';
  className?: string;
}

// MITRE ATT&CK tactic colors
const TACTIC_COLORS: Record<string, string> = {
  reconnaissance: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  'resource-development': 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  'initial-access': 'bg-red-600/20 text-red-300 border-red-600/30',
  execution: 'bg-orange-600/20 text-orange-300 border-orange-600/30',
  persistence: 'bg-yellow-600/20 text-yellow-300 border-yellow-600/30',
  'privilege-escalation': 'bg-amber-500/20 text-amber-300 border-amber-500/30',
  'defense-evasion': 'bg-lime-600/20 text-lime-300 border-lime-600/30',
  'credential-access': 'bg-green-600/20 text-green-300 border-green-600/30',
  discovery: 'bg-teal-500/20 text-teal-300 border-teal-500/30',
  'lateral-movement': 'bg-cyan-600/20 text-cyan-300 border-cyan-600/30',
  collection: 'bg-blue-600/20 text-blue-300 border-blue-600/30',
  'command-and-control': 'bg-indigo-600/20 text-indigo-300 border-indigo-600/30',
  exfiltration: 'bg-violet-600/20 text-violet-300 border-violet-600/30',
  impact: 'bg-purple-600/20 text-purple-300 border-purple-600/30',
};

function getTacticColor(tactic: string) {
  const key = tactic.toLowerCase().replace(/ /g, '-').replace(/_/g, '-');
  return TACTIC_COLORS[key] ?? 'bg-gray-700/30 text-gray-400 border-gray-700/50';
}

export function MitreBadge({ tactic, technique, techniqueId, size = 'md', className = '' }: MitreBadgeProps) {
  const colorClass = tactic ? getTacticColor(tactic) : 'bg-gray-700/30 text-gray-400 border-gray-700/50';
  const sizeClass = size === 'sm' ? 'text-xs px-1.5 py-0.5' : 'text-xs px-2 py-1';

  return (
    <span className={`inline-flex items-center gap-1 rounded border font-mono ${sizeClass} ${colorClass} ${className}`}>
      {techniqueId && <span className="font-bold">{techniqueId}</span>}
      {technique || tactic}
    </span>
  );
}

interface MitreAttackListProps {
  attacks: Array<{
    tactic_name?: string;
    technique_name?: string;
    technique_id?: string;
  }>;
  maxVisible?: number;
  className?: string;
}

export function MitreAttackList({ attacks, maxVisible = 5, className = '' }: MitreAttackListProps) {
  const visible = attacks.slice(0, maxVisible);
  const overflow = attacks.length - maxVisible;

  return (
    <div className={`flex flex-wrap gap-1 ${className}`}>
      {visible.map((a, i) => (
        <MitreBadge
          key={i}
          tactic={a.tactic_name}
          technique={a.technique_name}
          techniqueId={a.technique_id}
          size="sm"
        />
      ))}
      {overflow > 0 && (
        <span className="text-xs text-gray-500 self-center">+{overflow} more</span>
      )}
    </div>
  );
}
