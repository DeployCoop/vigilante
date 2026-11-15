'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { errorMessage } from '@/lib/envelope';
import {
  Flame,
  Play,
  RefreshCw,
  Search,
  Terminal,
} from 'lucide-react';

interface Playbook {
  id: string;
  name: string;
  description: string;
  category?: string;
  severity?: string;
  mitreTechniques: { id: string; name: string }[];
  tags?: string[];
}

export default function ThreatSimPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [targetNamespace, setTargetNamespace] = useState<string>('opensearch');
  const [filterText, setFilterText] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [executing, setExecuting] = useState<boolean>(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const fetchPlaybooks = useCallback(() => {
    fetch('/api/threatsim')
      .then((res) => res.json())
      .then((d) => {
        if (d.success) {
          setPlaybooks(d.playbooks || []);
          if (d.playbooks?.length > 0) {
            setSelectedPlaybook((prev) => prev ?? d.playbooks[0]);
          }
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchPlaybooks();
  }, [fetchPlaybooks]);

  const handleRunPlaybook = async () => {
    if (!selectedPlaybook) return;
    setExecuting(true);
    setLogs([`🚀 Initializing Threat Simulation: ${selectedPlaybook.name}...`]);
    try {
      const res = await fetch('/api/threatsim', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          playbookId: selectedPlaybook.id,
          namespace: targetNamespace
        })
      });
      const data = await res.json();
      if (data.success) {
        setLogs(data.logs || ['Simulation events dispatched successfully to SIEM.']);
        setStatusMessage(`✔ Completed simulation: ${selectedPlaybook.name}`);
        setTimeout(() => setStatusMessage(null), 4000);
      } else {
        setLogs((prev) => [...prev, `Error: ${data.error}`]);
      }
    } catch (err: unknown) {
      setLogs((prev) => [...prev, `Error: ${errorMessage(err)}`]);
    } finally {
      setExecuting(false);
    }
  };

  const filteredPlaybooks = playbooks.filter((p) => {
    const query = filterText.toLowerCase();
    return (
      p.id.toLowerCase().includes(query) ||
      p.name.toLowerCase().includes(query) ||
      p.category?.toLowerCase().includes(query) ||
      p.tags?.some((t: string) => t.toLowerCase().includes(query))
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-400">
            <Flame className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Threat Simulation Engine & Attack Playbooks
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-950 border border-orange-800 text-orange-300">
                MITRE / NIST SP 800-61
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Inject synthetic adversary attack vectors, lateral movement, and precursor telemetry into OpenSearch SIEM.
            </p>
          </div>
        </div>

        <button
          onClick={fetchPlaybooks}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-orange-950/60 border border-orange-800 text-orange-300 font-mono text-xs">
          {statusMessage}
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Left: Playbooks Catalog */}
        <div className="space-y-4 lg:col-span-1">
          <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
            <div className="flex items-center gap-2 bg-slate-900 p-2 rounded-lg border border-slate-800">
              <Search className="w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search playbooks by tag or name..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                className="bg-transparent border-none text-xs text-slate-200 placeholder-slate-500 focus:outline-none w-full"
              />
            </div>

            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {filteredPlaybooks.map((p) => (
                <div
                  key={p.id}
                  onClick={() => setSelectedPlaybook(p)}
                  className={`p-3 rounded-lg border cursor-pointer transition-all space-y-1.5 ${
                    selectedPlaybook?.id === p.id
                      ? 'bg-orange-950/40 border-orange-500/50 text-white'
                      : 'bg-slate-900/40 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold text-xs flex items-center justify-between">
                    <span>{p.name}</span>
                    <span className="text-[10px] text-orange-400 uppercase">{p.severity || 'MED'}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 line-clamp-2">{p.description}</p>
                  <div className="flex flex-wrap gap-1 pt-1">
                    {(p.tags || []).slice(0, 3).map((tag: string, i: number) => (
                      <span key={i} className="px-1.5 py-0.2 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-500">
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Selected Playbook Details & Execution Output */}
        <div className="lg:col-span-2 space-y-4">
          {selectedPlaybook ? (
            <div className="space-y-4">
              {/* Playbook Info Box */}
              <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <span>{selectedPlaybook.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-orange-950 text-orange-400 border border-orange-800 uppercase">
                      {selectedPlaybook.category}
                    </span>
                  </h3>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500">Target NS:</span>
                    <input
                      type="text"
                      value={targetNamespace}
                      onChange={(e) => setTargetNamespace(e.target.value)}
                      className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 text-xs w-28 focus:outline-none"
                    />
                  </div>
                </div>

                <p className="text-slate-400 text-xs leading-relaxed">{selectedPlaybook.description}</p>

                {selectedPlaybook.mitreTechniques && (
                  <div className="flex flex-wrap gap-2 pt-1">
                    {selectedPlaybook.mitreTechniques.map((m, i: number) => (
                      <span key={i} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-purple-300 text-[10px]">
                        {m.id}: {m.name}
                      </span>
                    ))}
                  </div>
                )}

                <div className="pt-2">
                  <button
                    onClick={handleRunPlaybook}
                    disabled={executing}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-orange-600 hover:bg-orange-500 disabled:bg-orange-900 text-white font-bold text-xs transition-colors shadow-lg shadow-orange-900/20"
                  >
                    {executing ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Injecting Attack Vector...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        <span>Execute Attack Playbook</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Execution Console Output */}
              <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-2">
                <div className="text-slate-400 font-bold uppercase text-[11px] pb-1 border-b border-slate-800 flex items-center justify-between">
                  <span>Simulation Telemetry Output</span>
                  <Terminal className="w-3.5 h-3.5 text-orange-400" />
                </div>
                <div className="bg-black/70 p-4 rounded-lg border border-slate-900 text-orange-300 font-mono text-[11px] leading-relaxed max-h-64 overflow-y-auto space-y-1">
                  {logs.length === 0 ? (
                    <div className="text-slate-600">Console idle. Click &quot;Execute Attack Playbook&quot; to begin.</div>
                  ) : (
                    logs.map((log, idx) => <div key={idx}>{log}</div>)
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-96 rounded-xl border border-slate-800 bg-slate-950/40 flex flex-col items-center justify-center text-center p-6 space-y-3 text-slate-500">
              <Flame className="w-8 h-8 text-slate-600" />
              <p>Select an attack playbook from the catalog to configure and execute.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
