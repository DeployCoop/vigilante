'use client';

import React, { useState, useEffect } from 'react';
import {
  Server,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Terminal,
  FileText,
  Copy,
  Check,
  ChevronRight,
  X
} from 'lucide-react';

interface PodItem {
  namespace: string;
  name: string;
  ready: string;
  status: string;
  restarts: number;
  age: string;
  ip: string;
  node: string;
}

export default function PodsPage() {
  const [pods, setPods] = useState<PodItem[]>([]);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [selectedNamespace, setSelectedNamespace] = useState<string>('all');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [clusterName, setClusterName] = useState<string>('vigilante-dev');
  const [activeModal, setActiveModal] = useState<{
    pod: PodItem;
    action: 'logs' | 'describe';
    content: string;
    loading: boolean;
  } | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchPods = (ns = selectedNamespace) => {
    setLoading(true);
    fetch(`/api/pods?namespace=${ns}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setPods(data.pods || []);
          if (data.namespaces) setNamespaces(['all', ...data.namespaces]);
          if (data.clusterName) setClusterName(data.clusterName);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchPods(selectedNamespace);
    const interval = setInterval(() => {
      fetchPods(selectedNamespace);
    }, 5000);
    return () => clearInterval(interval);
  }, [selectedNamespace]);

  const handleInspect = async (pod: PodItem, action: 'logs' | 'describe') => {
    setActiveModal({ pod, action, content: '', loading: true });
    try {
      const res = await fetch(`/api/pods?namespace=${pod.namespace}&pod=${pod.name}&action=${action}`);
      const data = await res.json();
      setActiveModal({
        pod,
        action,
        content: data.output || '(No output returned)',
        loading: false
      });
    } catch (err: any) {
      setActiveModal({
        pod,
        action,
        content: `Error: ${err.message}`,
        loading: false
      });
    }
  };

  const filteredPods = pods.filter((p) => {
    const matchesSearch =
      p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.namespace.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.ip.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  const getStatusBadge = (status: string) => {
    if (status === 'Running' || status === 'Completed') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800">
          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          {status}
        </span>
      );
    }
    if (status.includes('Init') || status === 'Pending') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-amber-950/80 text-amber-400 border border-amber-800">
          <Clock className="w-3 h-3 text-amber-400 animate-spin" />
          {status}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-rose-950/80 text-rose-400 border border-rose-800">
        <XCircle className="w-3 h-3 text-rose-400" />
        {status}
      </span>
    );
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
              Kubernetes Live Pods & Workload Telemetry
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                k3d-{clusterName}
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Live equivalent to <code>kubectl get pods -A -o wide</code> with container log streaming and pod describe.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchPods(selectedNamespace)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-800">
        <div className="flex items-center gap-2 flex-1">
          <Search className="w-4 h-4 text-slate-500 ml-1" />
          <input
            type="text"
            placeholder="Search pods by name, IP, or namespace..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-transparent border-none text-xs text-slate-200 placeholder-slate-500 focus:outline-none w-full font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-xs text-slate-400 font-mono">Namespace:</span>
          <select
            value={selectedNamespace}
            onChange={(e) => setSelectedNamespace(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs rounded-lg px-2.5 py-1 text-slate-300 font-mono focus:outline-none"
          >
            {namespaces.map((ns) => (
              <option key={ns} value={ns}>
                {ns}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Pods Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950/60">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[10px]">
            <tr>
              <th className="py-3 px-4">Namespace</th>
              <th className="py-3 px-4">Pod Name</th>
              <th className="py-3 px-4">Ready</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Restarts</th>
              <th className="py-3 px-4">Age</th>
              <th className="py-3 px-4">IP</th>
              <th className="py-3 px-4">Node</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-slate-300">
            {filteredPods.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-slate-500 font-mono">
                  {loading ? 'Polling Kubernetes pods...' : 'No matching pods found in cluster context.'}
                </td>
              </tr>
            ) : (
              filteredPods.map((p) => (
                <tr key={`${p.namespace}/${p.name}`} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-3 px-4 font-semibold text-cyan-400">{p.namespace}</td>
                  <td className="py-3 px-4 text-white font-medium max-w-[280px] truncate" title={p.name}>
                    {p.name}
                  </td>
                  <td className="py-3 px-4 text-slate-400">{p.ready}</td>
                  <td className="py-3 px-4">{getStatusBadge(p.status)}</td>
                  <td className="py-3 px-4">
                    <span className={p.restarts > 0 ? 'text-amber-400 font-bold' : 'text-slate-500'}>
                      {p.restarts}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-400">{p.age}</td>
                  <td className="py-3 px-4 text-slate-400">{p.ip}</td>
                  <td className="py-3 px-4 text-slate-500 text-[11px] truncate max-w-[120px]">{p.node}</td>
                  <td className="py-3 px-4 text-right">
                    <div className="inline-flex items-center gap-1.5">
                      <button
                        onClick={() => handleInspect(p, 'logs')}
                        title="Stream Pod Logs"
                        className="p-1 rounded bg-slate-900 hover:bg-cyan-950 hover:text-cyan-400 text-slate-400 border border-slate-800 transition-colors"
                      >
                        <Terminal className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleInspect(p, 'describe')}
                        title="Describe Pod"
                        className="p-1 rounded bg-slate-900 hover:bg-emerald-950 hover:text-emerald-400 text-slate-400 border border-slate-800 transition-colors"
                      >
                        <FileText className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Inspect Modal (Describe / Logs) */}
      {activeModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-4xl bg-slate-950 border border-slate-800 rounded-xl overflow-hidden flex flex-col max-h-[85vh] shadow-2xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
              <div className="flex items-center gap-2">
                <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  {activeModal.action}
                </span>
                <span className="font-mono text-sm font-bold text-white">
                  {activeModal.pod.namespace} / {activeModal.pod.name}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(activeModal.content);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
                <button
                  onClick={() => setActiveModal(null)}
                  className="p-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="p-4 overflow-y-auto flex-1 font-mono text-xs text-slate-300 bg-black/60 leading-relaxed whitespace-pre-wrap selection:bg-cyan-500/30">
              {activeModal.loading ? (
                <div className="flex items-center gap-2 text-cyan-400 py-8 justify-center">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Loading {activeModal.action} output from cluster...</span>
                </div>
              ) : (
                activeModal.content
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
