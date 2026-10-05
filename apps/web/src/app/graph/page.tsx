'use client';

import React, { useState, useEffect } from 'react';
import {
  Share2,
  AlertTriangle,
  Shield,
  Layers,
  Server,
  Key,
  CheckCircle2,
  RefreshCw,
  Zap
} from 'lucide-react';

export default function AttackGraphPage() {
  const [graphData, setGraphData] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<string>('sa-cluster-admin');
  const [loading, setLoading] = useState<boolean>(true);

  const fetchGraph = (target: string) => {
    setLoading(true);
    fetch(`/api/graph?target=${encodeURIComponent(target)}`)
      .then((res) => res.json())
      .then((data) => {
        setGraphData(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchGraph(selectedNode);
  }, []);

  const handleSelectNode = (nodeId: string) => {
    setSelectedNode(nodeId);
    fetchGraph(nodeId);
  };

  const blast = graphData?.blast;
  const nodes = graphData?.graph?.nodes || [];
  const edges = graphData?.graph?.edges || [];

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <Share2 className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Composite Attack Graph & Blast-Radius Engine
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300">
                Multi-Hop Lateral Movement
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Federating Nmap, Kubernetes RBAC, and BloodHound telemetry into an automated compromise traversal graph.
            </p>
          </div>
        </div>

        {blast && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            <span>Simulated Blast Impact:</span>
            <strong className={`${
              blast.riskLevel === 'CRITICAL' ? 'text-rose-400' :
              blast.riskLevel === 'HIGH' ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {blast.impactScore}/100 [{blast.riskLevel}]
            </strong>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Visual Graph View */}
        <div className="lg:col-span-2 rounded-2xl border border-slate-800 bg-[#070a13] p-6 min-h-[500px] flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 border-b border-slate-800 pb-3">
            <span>Directional Kill Chain: Attacker ➔ Target Node</span>
            <span>Click any node to evaluate blast radius</span>
          </div>

          <div className="flex-1 flex items-center justify-center p-4 overflow-auto">
            {loading ? (
              <RefreshCw className="w-6 h-6 animate-spin text-purple-400" />
            ) : (
              <div className="flex flex-wrap items-center justify-center gap-4 py-8">
                {nodes.map((n: any, idx: number) => {
                  const isSelected = n.id === selectedNode;
                  const isCrit = n.type === 'identity' || n.id === 'sa-cluster-admin';

                  return (
                    <div
                      key={n.id}
                      onClick={() => handleSelectNode(n.id)}
                      className={`p-4 rounded-xl border text-xs font-mono cursor-pointer transition-all hover:scale-105 ${
                        isSelected
                          ? 'bg-purple-950/60 border-purple-400 shadow-lg shadow-purple-500/20'
                          : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center gap-2 pb-1">
                        {n.type === 'identity' ? (
                          <Key className="w-4 h-4 text-amber-400" />
                        ) : (
                          <Server className="w-4 h-4 text-cyan-400" />
                        )}
                        <span className="font-bold text-white">{n.label || n.id}</span>
                      </div>
                      <div className="text-[10px] text-slate-500">Type: {n.type}</div>
                      <div className="text-[10px] text-slate-400 pt-1">Zone: {n.zone || 'Internal'}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Shortest Path Breadcrumb */}
          {graphData?.shortestPath && (
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono">
              <span className="text-slate-500">Shortest Exploit Path to cluster-admin:</span>
              <div className="text-cyan-400 pt-1 flex flex-wrap items-center gap-2">
                {graphData.shortestPath.map((step: string, i: number) => (
                  <React.Fragment key={i}>
                    <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-white font-semibold">
                      {step}
                    </span>
                    {i < graphData.shortestPath.length - 1 && <span className="text-slate-600">➔</span>}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Blast Radius Impact Drawer */}
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5 space-y-4 font-mono text-xs">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="font-bold text-white text-sm">Blast Radius Assessment</h3>
            <span className="text-slate-400 text-[11px]">Selected: <strong className="text-purple-400">{selectedNode}</strong></span>
          </div>

          {blast ? (
            <div className="space-y-4">
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                <span className="text-slate-500">Calculated Impact Score</span>
                <div className="text-2xl font-bold text-white pt-1">
                  {blast.impactScore}/100 <span className="text-xs text-rose-400">[{blast.riskLevel}]</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold">Reachable Downstream Assets ({blast.reachableCount})</span>
                <div className="space-y-1 pt-1.5">
                  {(blast.compromisedBreakdown?.workloads || []).map((w: string, i: number) => (
                    <div key={i} className="p-2 rounded bg-slate-900/60 border border-slate-800 text-[11px] text-slate-300">
                      • Workload: {w}
                    </div>
                  ))}
                  {(blast.compromisedBreakdown?.identities || []).map((id: string, i: number) => (
                    <div key={i} className="p-2 rounded bg-amber-950/20 border border-amber-900 text-[11px] text-amber-300">
                      • Identity: {id}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="text-slate-500 italic">Select a node to calculate blast radius impact</div>
          )}
        </div>
      </div>
    </div>
  );
}
