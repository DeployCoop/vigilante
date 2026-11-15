'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  RefreshCw,
  Plus,
  Bell,
  CheckCircle2,
  AlertTriangle,
  Lock,
  X
} from 'lucide-react';
import { errorMessage } from '@/lib/envelope';

interface Canary {
  id: string;
  name: string;
  namespace: string;
  type: string;
  tripped: boolean;
  lastTrippedBy?: string;
}

export default function DeceptionPage() {
  const [canaries, setCanaries] = useState<Canary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isDeployModalOpen, setIsDeployModalOpen] = useState<boolean>(false);
  const [deployType, setDeployType] = useState<string>('smb');
  const [deployName, setDeployName] = useState<string>('');
  const [deployNamespace, setDeployNamespace] = useState<string>('default');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const fetchCanaries = () => {
    fetch('/api/deception')
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setCanaries(data.canaries || []);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchCanaries();
  }, []);

  const handleTriggerAlarm = async (canaryId: string) => {
    try {
      const res = await fetch('/api/deception', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'alarm', canaryId })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage(`🚨 Canary alarm triggered! Simulated adversary tripwire logged.`);
        fetchCanaries();
        setTimeout(() => setStatusMessage(null), 4000);
      }
    } catch (err: unknown) {
      setStatusMessage(`Error triggering alarm: ${errorMessage(err)}`);
    }
  };

  const handleDeploy = async () => {
    try {
      const res = await fetch('/api/deception', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'deploy',
          type: deployType,
          name: deployName.trim() || undefined,
          namespace: deployNamespace
        })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage(`✔ Generated decoy manifest for ${deployType}!`);
        setIsDeployModalOpen(false);
        fetchCanaries();
        setTimeout(() => setStatusMessage(null), 4000);
      }
    } catch (err: unknown) {
      setStatusMessage(`Error: ${errorMessage(err)}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-yellow-500/10 border border-yellow-500/30 text-yellow-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Autonomous Deception Mesh (&quot;Canary Kube&quot;)
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-yellow-950 border border-yellow-800 text-yellow-300">
                Active Honeynet
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Deploy decoy ServiceAccounts, canary secret tokens, and honeypot network services with automated SOAR tripwires.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => setIsDeployModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-yellow-500 hover:bg-yellow-400 text-slate-950 font-bold transition-colors shadow-lg shadow-yellow-500/20"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Deploy Canary Asset</span>
          </button>

          <button
            onClick={fetchCanaries}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-yellow-950/60 border border-yellow-800 text-yellow-300 font-mono text-xs">
          {statusMessage}
        </div>
      )}

      {/* Canaries Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
        {canaries.length === 0 ? (
          <div className="col-span-full p-8 rounded-xl border border-slate-800 bg-slate-950/60 text-center space-y-3">
            <Lock className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-slate-400">No active deception assets currently registered in the cluster.</p>
            <p className="text-[11px] text-slate-500">
              Click &quot;Deploy Canary Asset&quot; above to seed decoy credentials, ServiceAccounts, or network honeypots.
            </p>
          </div>
        ) : (
          canaries.map((c) => (
            <div
              key={c.id}
              className={`p-5 rounded-xl border transition-all space-y-3 ${
                c.tripped
                  ? 'bg-rose-950/30 border-rose-800 shadow-lg shadow-rose-950/20'
                  : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 border ${
                    c.tripped
                      ? 'bg-rose-950 text-rose-300 border-rose-800 animate-pulse'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}
                >
                  {c.tripped ? <AlertTriangle className="w-3 h-3" /> : <CheckCircle2 className="w-3 h-3" />}
                  {c.tripped ? '🚨 TRIPPED' : '🟢 ARMED'}
                </span>
                <span className="text-[10px] text-slate-500 uppercase">[{c.type}]</span>
              </div>

              <div>
                <div className="font-bold text-white text-sm">{c.name}</div>
                <div className="text-[11px] text-slate-400">Namespace: {c.namespace}</div>
              </div>

              {c.tripped && c.lastTrippedBy && (
                <div className="p-2 rounded bg-rose-950/50 border border-rose-900/60 text-[11px] text-rose-300">
                  Tripped by: <strong>{c.lastTrippedBy}</strong>
                </div>
              )}

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[10px] text-slate-500 truncate max-w-[140px]">{c.id}</span>
                {!c.tripped && (
                  <button
                    onClick={() => handleTriggerAlarm(c.id)}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-900 hover:bg-rose-950 hover:text-rose-400 text-slate-400 border border-slate-800 text-[10px]"
                  >
                    <Bell className="w-3 h-3" />
                    <span>Test Alarm</span>
                  </button>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {/* Deploy Modal */}
      {isDeployModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl font-mono text-xs">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <span className="font-bold text-white text-sm">Deploy Autonomous Canary Asset</span>
              <button onClick={() => setIsDeployModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <div className="space-y-1.5">
                <label className="text-slate-400">Canary Asset Type:</label>
                <select
                  value={deployType}
                  onChange={(e) => setDeployType(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none"
                >
                  <option value="smb">Decoy SMB File Share (Port 445)</option>
                  <option value="ssh">Decoy SSH Shell Service (Port 22)</option>
                  <option value="redis">Decoy Redis Memory Store (Port 6379)</option>
                  <option value="mssql">Decoy MS SQL Server (Port 1433)</option>
                  <option value="sa">Decoy ServiceAccount (Fake Cluster-Admin)</option>
                  <option value="secret">Honeytoken Secret (Fake DB Password)</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-400">Asset Name (Optional):</label>
                <input
                  type="text"
                  placeholder="e.g. backup-storage-decoy"
                  value={deployName}
                  onChange={(e) => setDeployName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-white placeholder-slate-600 focus:outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-400">Target Namespace:</label>
                <input
                  type="text"
                  value={deployNamespace}
                  onChange={(e) => setDeployNamespace(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none"
                />
              </div>

              <button
                onClick={handleDeploy}
                className="w-full py-2.5 rounded-lg bg-yellow-500 hover:bg-yellow-400 text-slate-950 font-bold text-xs transition-colors"
              >
                Provision Canary
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
