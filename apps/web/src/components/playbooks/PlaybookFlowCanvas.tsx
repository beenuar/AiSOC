'use client';

/**
 * PlaybookFlowCanvas
 * ------------------
 * React Flow canvas that renders a playbook's steps as an interactive
 * directed graph. Steps are laid out top-to-bottom automatically.
 *
 * Props:
 *   steps        – array of PlaybookStep (read from Playbook.steps)
 *   onSelectStep – called when user clicks a node (for the sidebar panel)
 *   selectedId   – currently selected step id
 *   readOnly     – disables drag/add when true
 */

import React, { useCallback, useEffect, useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type Connection,
  type NodeTypes,
  BackgroundVariant,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { PlaybookStep } from './types';
import { STEP_TYPE_META } from './stepColors';

/* ─────────────────────────── Custom Node ─────────────────────────── */

interface StepNodeData {
  step: PlaybookStep;
  selected: boolean;
  onClick: (id: string) => void;
  [key: string]: unknown;
}

function StepNode({ data }: { data: StepNodeData }) {
  const { step, selected, onClick } = data;
  const meta = STEP_TYPE_META[step.type];
  return (
    <div
      onClick={() => onClick(step.id)}
      style={{
        border: selected ? `2px solid ${meta.color}` : '1px solid #374151',
        background: selected ? meta.bgColor : '#111827',
        borderRadius: 10,
        minWidth: 200,
        padding: '10px 14px',
        cursor: 'pointer',
        boxShadow: selected ? `0 0 12px ${meta.color}44` : 'none',
        transition: 'all 0.15s ease',
      }}
    >
      <div className="flex items-center gap-2 mb-1">
        <span style={{ fontSize: 16 }}>{meta.icon}</span>
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            color: meta.color,
          }}
        >
          {meta.label}
        </span>
      </div>
      <div style={{ color: '#f3f4f6', fontSize: 13, fontWeight: 500 }}>
        {step.name}
      </div>
      {step.condition && (
        <div
          style={{
            marginTop: 4,
            fontSize: 11,
            color: '#9ca3af',
            fontFamily: 'monospace',
          }}
        >
          if {step.condition.field} {step.condition.operator}{' '}
          {JSON.stringify(step.condition.value)}
        </div>
      )}
      <div style={{ marginTop: 4, display: 'flex', gap: 6 }}>
        {step.on_failure !== 'abort' && (
          <span
            style={{
              fontSize: 10,
              background: '#374151',
              color: '#9ca3af',
              borderRadius: 4,
              padding: '1px 5px',
            }}
          >
            on_failure: {step.on_failure}
          </span>
        )}
        {step.retry_max > 0 && (
          <span
            style={{
              fontSize: 10,
              background: '#374151',
              color: '#9ca3af',
              borderRadius: 4,
              padding: '1px 5px',
            }}
          >
            retry ×{step.retry_max}
          </span>
        )}
      </div>
    </div>
  );
}

const nodeTypes: NodeTypes = { stepNode: StepNode as never };

/* ─────────────────────────── Layout helper ─────────────────────────── */

const NODE_W = 220;
const NODE_H = 90;
const H_GAP = 60;
const V_GAP = 60;

function buildGraphElements(
  steps: PlaybookStep[],
  selectedId: string | null,
  onClickNode: (id: string) => void
): { nodes: Node[]; edges: Edge[] } {
  // Build adjacency from explicit next_true / next_false; fall back to sequential
  const nodes: Node[] = steps.map((step, idx) => ({
    id: step.id,
    type: 'stepNode',
    position: {
      x: step.type === 'condition' ? (idx % 2 === 0 ? 0 : NODE_W + H_GAP) : 0,
      y: idx * (NODE_H + V_GAP),
    },
    data: { step, selected: step.id === selectedId, onClick: onClickNode } as StepNodeData,
    draggable: true,
  }));

  const edges: Edge[] = [];
  const idSet = new Set(steps.map((s) => s.id));

  steps.forEach((step, idx) => {
    const color = STEP_TYPE_META[step.type].color;

    if (step.next_true && idSet.has(step.next_true)) {
      edges.push({
        id: `${step.id}-true`,
        source: step.id,
        target: step.next_true,
        label: 'true',
        style: { stroke: '#34d399' },
        labelStyle: { fill: '#34d399', fontWeight: 600, fontSize: 11 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#34d399' },
      });
    }
    if (step.next_false && idSet.has(step.next_false)) {
      edges.push({
        id: `${step.id}-false`,
        source: step.id,
        target: step.next_false,
        label: 'false',
        style: { stroke: '#f87171' },
        labelStyle: { fill: '#f87171', fontWeight: 600, fontSize: 11 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#f87171' },
      });
    } else if (!step.next_true && !step.next_false && idx < steps.length - 1) {
      // Sequential fallback
      edges.push({
        id: `${step.id}-seq`,
        source: step.id,
        target: steps[idx + 1].id,
        style: { stroke: color + '88' },
        markerEnd: { type: MarkerType.ArrowClosed, color },
        animated: false,
      });
    }
  });

  return { nodes, edges };
}

/* ─────────────────────────── Main Component ─────────────────────────── */

interface PlaybookFlowCanvasProps {
  steps: PlaybookStep[];
  onSelectStep: (id: string | null) => void;
  selectedId: string | null;
  readOnly?: boolean;
  onStepsChange?: (steps: PlaybookStep[]) => void;
}

export function PlaybookFlowCanvas({
  steps,
  onSelectStep,
  selectedId,
  readOnly = false,
  onStepsChange,
}: PlaybookFlowCanvasProps) {
  const handleNodeClick = useCallback(
    (id: string) => {
      onSelectStep(id === selectedId ? null : id);
    },
    [onSelectStep, selectedId]
  );

  const { nodes: initialNodes, edges: initialEdges } = useMemo(
    () => buildGraphElements(steps, selectedId, handleNodeClick),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [steps, selectedId]
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync when steps prop changes
  useEffect(() => {
    const { nodes: n, edges: e } = buildGraphElements(
      steps,
      selectedId,
      handleNodeClick
    );
    setNodes(n);
    setEdges(e);
  }, [steps, selectedId, handleNodeClick, setNodes, setEdges]);

  const onConnect = useCallback(
    (params: Connection) => {
      if (!readOnly) setEdges((eds) => addEdge(params, eds));
    },
    [setEdges, readOnly]
  );

  return (
    <div style={{ width: '100%', height: '100%', background: '#0d1117' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.3 }}
        nodesDraggable={!readOnly}
        nodesConnectable={!readOnly}
        elementsSelectable={true}
        onPaneClick={() => onSelectStep(null)}
        proOptions={{ hideAttribution: true }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="#1f2937"
        />
        <Controls
          style={{
            background: '#111827',
            border: '1px solid #374151',
            borderRadius: 8,
          }}
          showInteractive={false}
        />
        <MiniMap
          nodeColor={(n) => {
            const step = steps.find((s) => s.id === n.id);
            if (!step) return '#374151';
            return STEP_TYPE_META[step.type].color;
          }}
          style={{
            background: '#111827',
            border: '1px solid #374151',
            borderRadius: 8,
          }}
          maskColor="#0d111788"
        />
      </ReactFlow>
    </div>
  );
}
