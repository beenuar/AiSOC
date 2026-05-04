import type { StepType } from './types';

export const STEP_TYPE_META: Record<
  StepType,
  { label: string; color: string; bgColor: string; icon: string }
> = {
  enrich:         { label: 'Enrich',         color: '#60a5fa', bgColor: '#1e3a5f', icon: 'enr' },
  investigate:    { label: 'Investigate',    color: '#a78bfa', bgColor: '#2e1f5e', icon: 'inv' },
  notify:         { label: 'Notify',         color: '#34d399', bgColor: '#1a3d2e', icon: 'ntf' },
  block_ip:       { label: 'Block IP',       color: '#f87171', bgColor: '#3d1a1a', icon: 'blk' },
  isolate_host:   { label: 'Isolate Host',   color: '#fb923c', bgColor: '#3d2a1a', icon: 'iso' },
  create_ticket:  { label: 'Create Ticket',  color: '#fbbf24', bgColor: '#3d341a', icon: 'tkt' },
  close_case:     { label: 'Close Case',     color: '#94a3b8', bgColor: '#252d3a', icon: 'cls' },
  http:           { label: 'HTTP',           color: '#38bdf8', bgColor: '#1a3040', icon: 'http' },
  condition:      { label: 'Condition',      color: '#e879f9', bgColor: '#3a1a40', icon: 'if' },
};
