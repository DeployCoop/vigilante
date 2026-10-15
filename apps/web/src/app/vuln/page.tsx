'use client';

import React, { useState, useEffect } from 'react';
import {
  Brain,
  RefreshCw,
  ShieldAlert,
  Server,
  Network,
  Play,
  Share2,
  Lock,
  ChevronRight,
  ExternalLink,
  Cpu
} from 'lucide-react';

export default function VulnPage() {
  const [dossiers, setDossiers] = useState<any[]>([]);
  const [trafficPcaps, setTrafficPcaps] = useState<any[]>([]);
  const [bhIngests, setBhIngests] = useState<any[]>([]);
  const [selectedDossier, setSelectedDossier] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'dossiers' | 'pcaps' | 'identity'>('dossiers');
  const [loading, setLoading] = useState<boolean>(true);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const fetchVulnData = () => {
    setLoading(true);
    fetch('/api/dossier')
      .then((res) => res.json())
      .then((d) => {
        if (d.success) {
          setDossiers(d.dossiers || []);
          setTrafficPcaps(d.trafficPcaps || []);
          setBhIngests(d.bhIngests || []);
          if (d.dossiers?.length > 0 && !selectedDossier) {
            fetchDossierDetails(d.dossiers[0].target);
          }
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  const fetchDossierDetails = (target: string) => {
    fetch(`/api/dossier?target=${encodeURIComponent(target)}`)
      .then((res) => res.json())
      .then((d) => {
        if (d.success && d.dossier) {
          setSelectedDossier(d.dossier);
        }
      });
  };

  useEffect(() => {
    fetchVulnData();
  }, []);

  const handleReplayPcap = async (pcapFile: string) => {
    try {
      const res = await fetch('/api/dossier', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'replay', pcapFile })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage(`✔ PCAP replay executed!`);
        setTimeout(() => setStatusMessage(null), 3000);
      }
    } catch (err: any) {
      setStatusMessage(`Error replaying: ${err.message}`);
    }
  };

  const getRiskColor = (tier: string) => {
    switch (tier?.toUpperCase()) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-950/80 border-rose-800';
      case 'HIGH':
        return 'text-amber-400 bg-amber-950/80 border-amber-800';
      case 'MEDIUM':
        return 'text-yellow-400 bg-yellow-950/80 border-yellow-800';
      default:
        return 'text-cyan-400 bg-cyan-950/80 border-cyan-800';
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-pink-500/10 border border-pink-500/30 text-pink-400">
            <Brain className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Vulnerability & Threat Center (Dossiers & Brain)
              <span className="text-[10px] px-2 py-0.5 rounded bg-pink-950 border border-pink-800 text-pink-300">
                Threat Intelligence
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Unified host dossiers, normalized risk scoring, PCAP replay, and BloodHound identity graph paths.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-lg p-1">
            <button
              onClick={() => setActiveTab('dossiers')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'dossiers' ? 'bg-pink-500/20 text-pink-300 border border-pink-500/40' : 'text-slate-400'
              }`}
            >
              Host Dossiers ({dossiers.length})
            </button>
            <button
              onClick={() => setActiveTab('pcaps')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'pcaps' ? 'bg-pink-500/20 text-pink-300 border border-pink-500/40' : 'text-slate-400'
              }`}
            >
              PCAP Recordings ({trafficPcaps.length})
            </button>
            <button
              onClick={() => setActiveTab('identity')}
              className={`px-3 py-1.5 rounded transition-colors ${
                activeTab === 'identity' ? 'bg-pink-500/20 text-pink-300 border border-pink-500/40' : 'text-slate-400'
              }`}
            >
              Active Directory ({bhIngests.length})
            </button>
          </div>

          <button
            onClick={fetchVulnData}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-3 rounded-lg bg-pink-950/60 border border-pink-800 text-pink-300">
          {statusMessage}
        </div>
      )}

      {/* Tab Content */}
      {activeTab === 'dossiers' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Dossiers List */}
          <div className="space-y-4 lg:col-span-1">
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
              <div className="text-slate-400 font-bold uppercase text-[11px] pb-1 border-b border-slate-800 flex items-center justify-between">
                <span>Discovered Host Dossiers</span>
                <span>{dossiers.length} Target(s)</span>
              </div>

              <div className="space-y-2">
                {dossiers.map((d, i) => (
                  <div
                    key={i}
                    onClick={() => fetchDossierDetails(d.target)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all space-y-1 ${
                      selectedDossier?.target === d.target
                        ? 'bg-pink-950/40 border-pink-500/50 text-white'
                        : 'bg-slate-900/40 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold text-xs">
                      <span>{d.target}</span>
                      <span className={`text-[10px] px-2 py-0.2 rounded border ${getRiskColor(d.riskTier)}`}>
                        {d.riskTier || 'LOW'} ({d.riskScore || 25})
                      </span>
                    </div>
                    <div className="text-[10px] text-slate-500 flex items-center gap-3">
                      <span>Ports: {d.openPortsCount || 0}</span>
                      <span>CVEs: {d.cvesCount || 0}</span>
                      {d.isBmc && <span className="text-amber-400">BMC/IPMI</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Dossier Detail Inspection */}
          <div className="lg:col-span-2 space-y-4">
            {selectedDossier ? (
              <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <span>Host Dossier: {selectedDossier.target}</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded border ${getRiskColor(selectedDossier.riskTier)}`}>
                        {selectedDossier.riskTier} RISK ({selectedDossier.riskScore}/100)
                      </span>
                    </h3>
                    <p className="text-[11px] text-slate-500 pt-0.5">
                      Last Updated: {new Date(selectedDossier.updatedAt || Date.now()).toLocaleString()}
                    </p>
                  </div>
                </div>

                {/* Subsections */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                    <span className="text-slate-500 uppercase text-[10px]">Open Network Ports</span>
                    <div className="text-white font-bold">
                      {selectedDossier.network?.openPorts?.length || 0} Open
                    </div>
                    <div className="text-[10px] text-slate-400 truncate">
                      {selectedDossier.network?.openPorts?.map((p: any) => `${p.port}/${p.service}`).join(', ') || 'None'}
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
                    <span className="text-slate-500 uppercase text-[10px]">Out-of-Band Hardware</span>
                    <div className="text-white font-bold">
                      {selectedDossier.outOfBand?.detected ? 'BMC Detected' : 'No IPMI'}
                    </div>
                    <div className="text-[10px] text-slate-400">
                      {selectedDossier.outOfBand?.vendor || 'Standard Node'}
                    </div>
                  </div>
                </div>

                {/* Vulnerability details */}
                <div className="space-y-2 pt-2">
                  <div className="text-slate-400 font-bold uppercase text-[10px]">Identified Flaws & Exposures</div>
                  <div className="bg-black/60 p-3 rounded-lg border border-slate-900 text-slate-300 text-[11px] space-y-1.5">
                    {(selectedDossier.vulnerabilities?.cves || []).length === 0 ? (
                      <div className="text-slate-500">No active critical CVEs pinned to this dossier.</div>
                    ) : (
                      selectedDossier.vulnerabilities.cves.map((cve: any, idx: number) => (
                        <div key={idx} className="flex items-center justify-between">
                          <span className="text-rose-400 font-bold">{cve.id}</span>
                          <span className="text-slate-400">{cve.title || cve.description}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-96 rounded-xl border border-slate-800 bg-slate-950/40 flex flex-col items-center justify-center text-center p-6 space-y-3 text-slate-500">
                <Brain className="w-8 h-8 text-slate-600" />
                <p>Select a host dossier on the left to inspect its risk footprint.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* PCAPs Tab */}
      {activeTab === 'pcaps' && (
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
          <div className="p-3 bg-slate-900/80 border-b border-slate-800 text-slate-400 font-bold uppercase text-[11px]">
            Captured PCAP Recordings & Replay
          </div>
          <div className="divide-y divide-slate-800/60">
            {trafficPcaps.length === 0 ? (
              <div className="p-8 text-center text-slate-500">
                No PCAP captures discovered in <code>~/.vigilante/evidence/pcaps</code>.
              </div>
            ) : (
              trafficPcaps.map((p, idx) => (
                <div key={idx} className="p-4 flex items-center justify-between hover:bg-slate-900/30">
                  <div>
                    <div className="font-bold text-white">{p.fileName}</div>
                    <div className="text-[10px] text-slate-500">{p.filePath}</div>
                  </div>
                  <button
                    onClick={() => handleReplayPcap(p.filePath)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-pink-950/80 hover:bg-pink-900 text-pink-300 border border-pink-800 text-xs"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Replay PCAP</span>
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Identity Tab */}
      {activeTab === 'identity' && (
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-center space-y-3">
          <Share2 className="w-8 h-8 text-slate-600 mx-auto" />
          <h3 className="font-bold text-white text-sm">BloodHound Active Directory Ingestion</h3>
          <p className="text-slate-400 text-xs max-w-lg mx-auto">
            Inspect attack paths, Kerberoasting opportunities, and domain escalation paths in the integrated graph analyzer.
          </p>
        </div>
      )}
    </div>
  );
}
