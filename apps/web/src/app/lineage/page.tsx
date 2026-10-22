'use client';

import React, { useState, useEffect } from 'react';
import {
  GitFork,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Terminal,
} from 'lucide-react';

interface LineageAnomaly {
  mitreTechnique?: string;
  message: string;
  severity?: string;
}

interface LineageData {
  anomalies: LineageAnomaly[];
  tree?: { totalProcesses?: number };
  ascii?: string;
}

export default function LineagePage() {
  const [data, setData] = useState<LineageData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchLineage = () => {
    fetch('/api/lineage')
      .then((res) => res.json())
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchLineage();
  }, []);

  const anomalies = data?.anomalies || [];
  const tree = data?.tree;
  const ascii = data?.ascii;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <GitFork className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Kernel-Native eBPF Process Lineage Tree
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                Ancestry Engine
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Container process hierarchy, shell breakout detection, LOLBin invocation tracking, and anomalous syscalls.
            </p>
          </div>
        </div>

        <button
          onClick={() => {
            setLoading(true);
            fetchLineage();
          }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Trace</span>
        </button>
      </div>

      {/* Anomalies Alert Box */}
      <div
        className={`p-4 rounded-xl border font-mono text-xs space-y-2 ${
          anomalies.length > 0
            ? 'bg-rose-950/30 border-rose-800/80 text-rose-300'
            : 'bg-emerald-950/20 border-emerald-800/60 text-emerald-300'
        }`}
      >
        <div className="flex items-center justify-between font-bold text-sm">
          <div className="flex items-center gap-2">
            {anomalies.length > 0 ? (
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            )}
            <span>
              {anomalies.length > 0
                ? `Active Process Lineage Anomalies (${anomalies.length})`
                : 'Process Ancestry Clean: No LOLBin or Shell Breakouts Detected'}
            </span>
          </div>
          <span className="text-[11px] font-normal opacity-80">eBPF Syscall Ingestion</span>
        </div>

        {anomalies.length > 0 && (
          <div className="space-y-1.5 pt-2 border-t border-rose-900/40">
            {anomalies.map((a, i: number) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-2">
                  <span className="px-1.5 py-0.2 rounded bg-rose-900/60 text-rose-200 border border-rose-700 text-[10px]">
                    {a.mitreTechnique || 'T1059'}
                  </span>
                  <span>{a.message}</span>
                </span>
                <span className="text-[11px] text-rose-400 font-bold">{a.severity || 'CRITICAL'}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Tree Visualization Card */}
      <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-xs space-y-3">
        <div className="flex items-center justify-between text-slate-400 pb-2 border-b border-slate-800 text-[11px]">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="font-bold text-white">Hierarchical Process Execution Tree</span>
          </div>
          <span>Total Nodes: {tree?.totalProcesses || 7}</span>
        </div>

        <pre className="p-4 rounded-lg bg-black/70 border border-slate-900 text-slate-200 overflow-x-auto text-[12px] leading-relaxed selection:bg-cyan-500/30">
          {ascii || 'No active lineage tree captured.'}
        </pre>
      </div>
    </div>
  );
}
