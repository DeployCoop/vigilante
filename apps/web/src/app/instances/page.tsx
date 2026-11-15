'use client';

import React, { useState, useEffect } from 'react';
import {
  Server,
  RefreshCw,
  Plus,
  Trash2,
  X
} from 'lucide-react';
import { errorMessage } from '@/lib/envelope';

interface InstanceItem {
  instanceName: string;
  clusterName: string;
  provider?: 'k3d' | 'k3s';
  domain: string;
  ip: string;
  createdAt: string;
  deployedModules?: string[];
}

export default function InstancesPage() {
  const [instances, setInstances] = useState<InstanceItem[]>([]);
  const [activeCluster, setActiveCluster] = useState<string>('vigilante-dev');
  const [loading, setLoading] = useState<boolean>(true);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [newInstanceName, setNewInstanceName] = useState<string>('');
  const [newDomain, setNewDomain] = useState<string>('vigilante.local');
  const [newProvider, setNewProvider] = useState<'k3d' | 'k3s'>('k3d');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const fetchInstances = () => {
    fetch('/api/instances')
      .then((res) => res.json())
      .then((d) => {
        if (d.success) {
          setInstances(d.instances || []);
          if (d.activeCluster) setActiveCluster(d.activeCluster);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchInstances();
  }, []);

  const handleCreateInstance = async () => {
    if (!newInstanceName.trim()) return;
    try {
      const res = await fetch('/api/instances', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          instanceName: newInstanceName.trim(),
          domain: newDomain.trim(),
          provider: newProvider
        })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage(`✔ Registered instance metadata for '${newInstanceName}' (${newProvider.toUpperCase()})`);
        setIsModalOpen(false);
        setNewInstanceName('');
        setNewProvider('k3d');
        fetchInstances();
        setTimeout(() => setStatusMessage(null), 4000);
      }
    } catch (err: unknown) {
      setStatusMessage(`Error: ${errorMessage(err)}`);
    }
  };

  const handleDeleteInstance = async (instanceName: string) => {
    if (!confirm(`Are you sure you want to delete instance '${instanceName}'?`)) return;
    try {
      const res = await fetch(`/api/instances?instanceName=${encodeURIComponent(instanceName)}&deleteCluster=true`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage(`✔ Deleted instance '${instanceName}'`);
        fetchInstances();
        setTimeout(() => setStatusMessage(null), 4000);
      }
    } catch (err: unknown) {
      setStatusMessage(`Error deleting: ${errorMessage(err)}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Cluster Instances Manager
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                Multi-Cluster Orchestration
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Manage isolated multi-cluster k3d and native host k3s instances, directories, TLS certificates, and domain ingress mappings.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-colors shadow-lg shadow-cyan-500/20"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Create Instance</span>
          </button>

          <button
            onClick={() => {
              setLoading(true);
              fetchInstances();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-300 font-mono text-xs">
          {statusMessage}
        </div>
      )}

      {/* Instances Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono text-xs">
        {instances.length === 0 ? (
          <div className="col-span-full p-8 rounded-xl border border-slate-800 bg-slate-950/60 text-center space-y-3">
            <Server className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-slate-400">No managed cluster instances found.</p>
            <p className="text-[11px] text-slate-500">
              Click &quot;Create Instance&quot; above to register a new k3d or k3s cluster workspace.
            </p>
          </div>
        ) : (
          instances.map((inst) => {
            const provider = inst.provider || 'k3d';
            return (
              <div
                key={inst.instanceName}
                className={`p-5 rounded-xl border transition-all space-y-3 ${
                  inst.instanceName === activeCluster
                    ? 'bg-cyan-950/20 border-cyan-500/40 shadow-lg shadow-cyan-950/20'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white text-sm">
                      {inst.instanceName}
                    </span>
                    <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold border ${
                      provider === 'k3s'
                        ? 'bg-amber-950/40 text-amber-300 border-amber-800/60'
                        : 'bg-blue-950/40 text-blue-300 border-blue-800/60'
                    }`}>
                      {provider.toUpperCase()}
                    </span>
                    {inst.instanceName === activeCluster && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold">
                        ACTIVE
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-slate-500">
                    {provider === 'k3s' ? `k3s-${inst.clusterName}` : `k3d-${inst.clusterName}`}
                  </span>
                </div>

                <div className="space-y-1 text-[11px] text-slate-400">
                  <div>Domain: <strong className="text-cyan-400">*.{inst.domain || 'vigilante.local'}</strong></div>
                  <div>IP Binding: <strong>{inst.ip || '127.0.0.1'}</strong></div>
                  <div>Provider Engine: <strong className="text-slate-300">{provider === 'k3s' ? 'K3s (Host Service)' : 'K3d (Containerized)'}</strong></div>
                  {inst.createdAt && (
                    <div className="text-[10px] text-slate-500">
                      Created: {new Date(inst.createdAt).toLocaleDateString()}
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="text-[10px] text-slate-500">
                    {inst.deployedModules?.length || 0} modules deployed
                  </span>
                  <button
                    onClick={() => handleDeleteInstance(inst.instanceName)}
                    title="Delete Cluster Instance"
                    className="p-1 rounded bg-slate-900 hover:bg-rose-950 hover:text-rose-400 text-slate-500 border border-slate-800 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl font-mono text-xs">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <span className="font-bold text-white text-sm">Create New Cluster Instance</span>
              <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <div className="space-y-1.5">
                <label className="text-slate-400">Cluster Provider Engine:</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setNewProvider('k3d')}
                    className={`p-2.5 rounded-lg border text-left transition-all ${
                      newProvider === 'k3d'
                        ? 'bg-cyan-950/50 border-cyan-500 text-white shadow-sm'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="font-bold flex items-center justify-between">
                      <span>k3d</span>
                      <span className="text-[10px] text-cyan-400">Docker</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-0.5">Containerized cluster</p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setNewProvider('k3s')}
                    className={`p-2.5 rounded-lg border text-left transition-all ${
                      newProvider === 'k3s'
                        ? 'bg-cyan-950/50 border-cyan-500 text-white shadow-sm'
                        : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="font-bold flex items-center justify-between">
                      <span>k3s</span>
                      <span className="text-[10px] text-amber-400">Native</span>
                    </div>
                    <p className="text-[10px] text-slate-400 mt-0.5">Host system service</p>
                  </button>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-400">Instance Name:</label>
                <input
                  type="text"
                  placeholder="e.g. vigilante-staging"
                  value={newInstanceName}
                  onChange={(e) => setNewInstanceName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-white placeholder-slate-600 focus:outline-none"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-400">Root Domain:</label>
                <input
                  type="text"
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-white focus:outline-none"
                />
              </div>

              <button
                onClick={handleCreateInstance}
                className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-colors"
              >
                Provision Instance Directory ({newProvider.toUpperCase()})
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
