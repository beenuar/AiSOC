/**
 * `/graph?entity=…` selects the node it names.
 *
 * Several callers already built that URL — the Investigation Rail's entity
 * chips (`services/api/app/services/alert_rail.py` emits `entity=host:…`,
 * `entity=ip:…`) and `HuntView`'s "Pivot to graph" button — and nothing read
 * it. The pivot navigated to the graph and dropped the entity, so the analyst
 * arrived at an unfiltered topology and had to find the node by eye.
 *
 * Federated search adds a third caller, so the parameter is now honoured.
 *
 * `GraphCanvas` drives cytoscape against a real canvas, which jsdom does not
 * provide, so the node-matching half is tested directly and the wiring is
 * covered by the type checker plus the production build.
 */

import { describe, expect, it } from 'vitest';
import { findNodeForEntityParam } from './AttackGraphView';
import type { GraphNode } from '@/lib/api';

const NODES: GraphNode[] = [
  { id: 'host:WIN-DC01', label: 'WIN-DC01', kind: 'asset' },
  { id: 'user:svc_backup', label: 'svc_backup', kind: 'user' },
  { id: 'ip:10.0.0.7', label: '10.0.0.7', kind: 'ip' },
];

describe('findNodeForEntityParam', () => {
  it('matches the typed form the rail and federated search emit', () => {
    expect(findNodeForEntityParam(NODES, 'host:WIN-DC01')?.id).toBe('host:WIN-DC01');
    expect(findNodeForEntityParam(NODES, 'ip:10.0.0.7')?.id).toBe('ip:10.0.0.7');
  });

  it('matches the bare form HuntView\u2019s pivot button emits', () => {
    // `HuntView` builds `/graph?entity=${host}` with no type prefix.
    expect(findNodeForEntityParam(NODES, 'WIN-DC01')?.id).toBe('host:WIN-DC01');
  });

  it('treats the type half as a hint, not a requirement', () => {
    // An operator pasting the wrong prefix should still land on the node.
    expect(findNodeForEntityParam(NODES, 'asset:WIN-DC01')?.id).toBe('host:WIN-DC01');
  });

  it('is case-insensitive on the value', () => {
    expect(findNodeForEntityParam(NODES, 'host:win-dc01')?.id).toBe('host:WIN-DC01');
  });

  it('selects nothing rather than guessing when there is no match', () => {
    expect(findNodeForEntityParam(NODES, 'host:NOT-IN-GRAPH')).toBeNull();
    expect(findNodeForEntityParam(NODES, '')).toBeNull();
    expect(findNodeForEntityParam(NODES, '   ')).toBeNull();
    expect(findNodeForEntityParam(NODES, 'host:')).toBeNull();
    expect(findNodeForEntityParam(NODES, null)).toBeNull();
    expect(findNodeForEntityParam([], 'host:WIN-DC01')).toBeNull();
  });

  it('prefers an id match over a label match', () => {
    const ambiguous: GraphNode[] = [
      { id: 'other', label: 'WIN-DC01', kind: 'asset' },
      { id: 'WIN-DC01', label: 'something-else', kind: 'asset' },
    ];
    expect(findNodeForEntityParam(ambiguous, 'WIN-DC01')?.id).toBe('WIN-DC01');
  });
});
