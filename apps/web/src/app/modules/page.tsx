'use client';

import React, { useState, useEffect } from 'react';
import {
  Layers,
  Server,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  ExternalLink,
  Shield,
  Activity
} from 'lucide-react';

export default function ModulesPage() {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchStatus = () => {
    setLoading(true);
    fetch('/api/status')
      .then((res) => res.json())
      .then((data) => {
        setStatus(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const modules = status?.modules || [];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Kubernetes Security Modules & Pod Infrastructure
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                k3d-vigilante-dev
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Manage installed modular security workloads across cluster namespaces.
            </p>
          </div>
        </div>

        <button
          onClick={fetchStatus}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Cluster</span>
        </button>
      </div>

      {/* Module Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {modules.map((m: any) => (
          <div
            key={m.id}
            className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 space-y-3 hover:border-slate-700 transition-all"
          >
            <div className="flex items-center justify-between">
              <span className="font-bold text-white text-sm">{m.name || m.id}</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold flex items-center gap-1 ${
                m.installed
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-slate-900 text-slate-500 border border-slate-800'
              }`}>
                {m.installed ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <AlertCircle className="w-3 h-3" />}
                {m.installed ? 'DEPLOYED' : 'NOT INSTALLED'}
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              {m.description || 'Modular security orchestration workload.'}
            </p>

            <div className="pt-2 border-t border-slate-800 text-[11px] font-mono text-slate-500 flex justify-between">
              <span>Namespace: <code>{m.namespace || 'kctf'}</code></span>
              <span>Port: {m.port || 'Auto'}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
