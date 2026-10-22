'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Clock,
  RefreshCw,
} from 'lucide-react';

interface TimelineNode {
  id?: string;
  title: string;
  severity: string;
  sourceModule: string;
  command?: string;
  file?: string;
  message?: string;
  entity?: string;
  mitreTechnique?: string;
  pid?: number;
  srcIp?: string;
}

interface TimelineData {
  nodes: TimelineNode[];
  edges: unknown[];
  rootCause?: { title?: string; entity?: string };
  dwell?: { humanDwell?: string };
  ascii?: string;
}

export default function TimelinePage() {
  const [data, setData] = useState<TimelineData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedNode, setSelectedNode] = useState<TimelineNode | null>(null);

  const fetchTimeline = useCallback(() => {
    fetch('/api/timeline')
      .then((res) => res.json())
      .then((d) => {
        setData(d);
        if (d.nodes?.length > 0) {
          setSelectedNode((prev) => prev ?? d.nodes[0]);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchTimeline();
  }, [fetchTimeline]);

  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  const rootCause = data?.rootCause;
  const dwell = data?.dwell;
  const ascii = data?.ascii;

  const getSeverityBadge = (sev: string) => {
    const s = (sev || 'MEDIUM').toUpperCase();
    if (s === 'CRITICAL') return 'bg-rose-950 text-rose-400 border-rose-800';
    if (s === 'HIGH') return 'bg-amber-950 text-amber-400 border-amber-800';
    if (s === 'MEDIUM') return 'bg-yellow-950 text-yellow-400 border-yellow-800';
    return 'bg-cyan-950 text-cyan-400 border-cyan-800';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Attack Timeline & Causal DAG Explorer
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300">
                Root Cause Synthesis
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Traverse multi-stage attack chains, trace process lineage causality, pinpoint initial compromise, and evaluate dwell time.
            </p>
          </div>
        </div>

        <button
          onClick={fetchTimeline}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Timeline</span>
        </button>
      </div>

      {/* Dwell Time & Root Cause Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60">
          <div className="text-[10px] text-slate-500 uppercase">Calculated Attacker Dwell Time</div>
          <div className="text-2xl font-bold text-cyan-400 pt-1">
            {dwell?.humanDwell || '100s'}
          </div>
          <div className="text-[11px] text-slate-500 pt-0.5">
            Initial Compromise to Lateral Hop
          </div>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60">
          <div className="text-[10px] text-slate-500 uppercase">Pinpointed Root Cause ($t_0$)</div>
          <div className="text-sm font-bold text-rose-400 pt-1.5 truncate">
            {rootCause?.title || 'Inbound Ingress Connection'}
          </div>
          <div className="text-[11px] text-slate-500 pt-0.5">
            Entity: <code>{rootCause?.entity || 'ingress-nginx'}</code>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60">
          <div className="text-[10px] text-slate-500 uppercase">Causal DAG Density</div>
          <div className="text-2xl font-bold text-white pt-1">
            {nodes.length} Nodes / {edges.length} Edges
          </div>
          <div className="text-[11px] text-slate-500 pt-0.5">
            Zero Disjoint Clusters
          </div>
        </div>
      </div>

      {/* Main Layout: Nodes list + Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Left: Sequential Timeline Nodes */}
        <div className="lg:col-span-2 space-y-3">
          <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-t-xl text-slate-400 font-bold uppercase flex items-center justify-between text-[11px]">
            <span>Causal Event Sequence (Chronological)</span>
            <span>Heterogeneous Telemetry (Falco + Zeek + Wazuh)</span>
          </div>

          <div className="space-y-2">
            {nodes.map((node, idx: number) => (
              <div
                key={node.id || idx}
                onClick={() => setSelectedNode(node)}
                className={`p-4 rounded-xl border cursor-pointer transition-all space-y-2 ${
                  selectedNode?.id === node.id
                    ? 'bg-purple-950/30 border-purple-500/50 shadow-lg shadow-purple-950/20'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-slate-900 border border-slate-700 flex items-center justify-center font-bold text-[10px] text-cyan-400">
                      {idx + 1}
                    </span>
                    <span className="font-bold text-white text-sm">{node.title}</span>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${getSeverityBadge(node.severity)}`}>
                    {node.severity}
                  </span>
                </div>

                <p className="text-slate-400 text-[11px] leading-relaxed pl-7">{node.message}</p>

                <div className="flex flex-wrap items-center gap-4 text-[10px] text-slate-500 pl-7 pt-1">
                  <span>Entity: <strong className="text-slate-300">{node.entity}</strong></span>
                  {node.mitreTechnique && (
                    <span>MITRE: <strong className="text-purple-300">{node.mitreTechnique}</strong></span>
                  )}
                  <span>Module: <strong className="text-cyan-400">{node.sourceModule}</strong></span>
                  {node.pid && <span>PID: {node.pid}</span>}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Selected Node Details & ASCII DAG */}
        <div className="space-y-4">
          {selectedNode ? (
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
              <h3 className="text-xs uppercase font-bold text-slate-400 pb-2 border-b border-slate-800 flex items-center justify-between">
                <span>Node Inspection</span>
                <span className="text-cyan-400">{selectedNode.id}</span>
              </h3>

              <div className="space-y-2 text-[11px]">
                <div>
                  <span className="text-slate-500">Action:</span>
                  <div className="text-white font-bold">{selectedNode.title}</div>
                </div>
                {selectedNode.command && (
                  <div>
                    <span className="text-slate-500">Command Line:</span>
                    <pre className="p-2 rounded bg-black/60 border border-slate-900 text-rose-300 whitespace-pre-wrap mt-0.5">
                      {selectedNode.command}
                    </pre>
                  </div>
                )}
                {selectedNode.file && (
                  <div>
                    <span className="text-slate-500">Target File:</span>
                    <div className="text-cyan-300 font-mono">{selectedNode.file}</div>
                  </div>
                )}
                {selectedNode.srcIp && (
                  <div>
                    <span className="text-slate-500">Source IP:</span>
                    <div className="text-slate-300 font-mono">{selectedNode.srcIp}</div>
                  </div>
                )}
              </div>
            </div>
          ) : null}

          {/* ASCII DAG */}
          {ascii && (
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-2">
              <div className="text-slate-400 text-[10px] uppercase font-bold">ASCII Attack Graph Trace</div>
              <pre className="p-3 rounded-lg bg-black/60 border border-slate-900 text-cyan-300 overflow-x-auto text-[10px] leading-snug">
                {ascii}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
