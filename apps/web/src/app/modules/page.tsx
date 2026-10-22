'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { errorMessage } from '@/lib/envelope';
import {
  Layers,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  ExternalLink,
  Download,
  Trash2,
  Terminal,
} from 'lucide-react';

interface ModuleEndpoint {
  name?: string;
  url: string;
}

interface ModuleItem {
  id: string;
  name?: string;
  installed: boolean;
  description?: string;
  endpoints: ModuleEndpoint[];
  dependencies?: string[];
}

export default function ModulesPage() {
  const [modules, setModules] = useState<ModuleItem[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState<string>('default');
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionLogs, setActionLogs] = useState<string[]>([]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const fetchModules = useCallback((ns: string) => {
    fetch(`/api/modules?namespace=${encodeURIComponent(ns)}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setModules(data.modules || []);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchModules(selectedNamespace);
  }, [selectedNamespace, fetchModules]);

  const handleModuleAction = async (moduleId: string, action: 'install' | 'uninstall') => {
    setActionLoading(`${action}-${moduleId}`);
    setActionLogs([`Starting ${action} for ${moduleId} in namespace ${selectedNamespace}...`]);
    try {
      const res = await fetch('/api/modules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          moduleId,
          namespace: selectedNamespace
        })
      });
      const data = await res.json();
      if (data.success) {
        setActionLogs(data.logs || [`Completed ${action} for ${moduleId}.`]);
        setStatusMessage(`✔ Successfully ${action}ed module '${moduleId}'!`);
        fetchModules(selectedNamespace);
        setTimeout(() => setStatusMessage(null), 4000);
      } else {
        setActionLogs((prev) => [...prev, `Error: ${data.error}`]);
      }
    } catch (err: unknown) {
      setActionLogs((prev) => [...prev, `Error: ${errorMessage(err)}`]);
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Security Modules & Multi-Tenant Stacks
              <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                k3d-vigilante-dev
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Deploy, inspect, and teardown modular security workloads (Suricata, Falco, Zeek, OpenVAS, Wazuh, kCTF) per namespace.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-slate-400">Target NS:</span>
            <select
              value={selectedNamespace}
              onChange={(e) => {
              setLoading(true);
              setSelectedNamespace(e.target.value);
            }}
              className="bg-slate-900 border border-slate-800 text-xs rounded-lg px-2.5 py-1.5 text-slate-200 focus:outline-none"
            >
              <option value="default">default</option>
              <option value="monitoring">monitoring</option>
              <option value="kctf">kctf</option>
              <option value="opensearch">opensearch</option>
              <option value="openvas">openvas</option>
            </select>
          </div>

          <button
            onClick={() => {
            setLoading(true);
            fetchModules(selectedNamespace);
          }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-300">
          {statusMessage}
        </div>
      )}

      {/* Module Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {modules.map((m) => {
          const isBusy = actionLoading === `install-${m.id}` || actionLoading === `uninstall-${m.id}`;

          return (
            <div
              key={m.id}
              className={`p-5 rounded-xl border space-y-3 transition-all ${
                m.installed
                  ? 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                  : 'bg-slate-950/40 border-slate-900 text-slate-500'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-white text-sm">{m.name || m.id}</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 border ${
                    m.installed
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-slate-900 text-slate-500 border border-slate-800'
                  }`}
                >
                  {m.installed ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <AlertCircle className="w-3 h-3" />}
                  {m.installed ? 'DEPLOYED' : 'UNINSTALLED'}
                </span>
              </div>

              <p className="text-[11px] text-slate-400 leading-relaxed min-h-[32px]">
                {m.description || 'Modular security orchestration workload.'}
              </p>

              {/* Endpoints */}
              {m.endpoints && m.endpoints.length > 0 && (
                <div className="pt-2 border-t border-slate-800/80 space-y-1">
                  <div className="text-[10px] text-slate-500 uppercase">Ingress Endpoints:</div>
                  <div className="flex flex-wrap gap-2">
                    {m.endpoints.map((ep, i: number) => (
                      <a
                        key={i}
                        href={ep.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
                      >
                        <span>{ep.name || ep.url}</span>
                        <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Actions */}
              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[10px] text-slate-500">
                  Deps: {m.dependencies?.length ? m.dependencies.join(', ') : 'None'}
                </span>

                <div className="flex items-center gap-2">
                  {m.installed ? (
                    <button
                      onClick={() => handleModuleAction(m.id, 'uninstall')}
                      disabled={isBusy}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-rose-950 hover:text-rose-400 text-slate-400 border border-slate-800 text-[11px] transition-colors"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>Uninstall</span>
                    </button>
                  ) : (
                    <button
                      onClick={() => handleModuleAction(m.id, 'install')}
                      disabled={isBusy}
                      className="flex items-center gap-1 px-3 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-[11px] font-bold transition-colors"
                    >
                      <Download className="w-3 h-3" />
                      <span>Deploy</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Action Logs Box */}
      {actionLogs.length > 0 && (
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-2">
          <div className="text-slate-400 font-bold uppercase text-[11px] pb-1 border-b border-slate-800 flex items-center justify-between">
            <span>Orchestration Event Logs</span>
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="bg-black/70 p-3 rounded-lg border border-slate-900 text-slate-300 text-[11px] leading-relaxed max-h-48 overflow-y-auto space-y-1">
            {actionLogs.map((log, idx) => (
              <div key={idx}>{log}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
