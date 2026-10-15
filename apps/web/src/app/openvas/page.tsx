'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Play,
  RefreshCw,
  Server,
  Lock,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Clock,
  ChevronRight,
  Info
} from 'lucide-react';

interface Finding {
  name: string;
  cvss: number;
  severity: { level: string; color: string; badge: string };
  port: string;
  nvtOid: string;
  summary: string;
  solution: string;
}

export default function OpenVASPage() {
  const [status, setStatus] = useState<any>(null);
  const [credentials, setCredentials] = useState<any>(null);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [discoveredHosts, setDiscoveredHosts] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [selectedHost, setSelectedHost] = useState<string>('127.0.0.1');
  const [customHost, setCustomHost] = useState<string>('');
  const [selectedProfile, setSelectedProfile] = useState<string>('full-and-fast');
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [activeReport, setActiveReport] = useState<any>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const fetchStatus = () => {
    setLoading(true);
    fetch('/api/openvas?action=status')
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setStatus(data.status);
          setCredentials(data.credentials);
          setProfiles(data.profiles || []);
          setDiscoveredHosts(data.discoveredHosts || []);
          setReports(data.reports || []);
          if (data.reports?.length > 0 && !activeReport) {
            setActiveReport(data.reports[0]);
          }
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleStartScan = async () => {
    const target = customHost.trim() || selectedHost;
    setScanning(true);
    try {
      const res = await fetch('/api/openvas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: target, profile: selectedProfile })
      });
      const data = await res.json();
      if (data.success && data.report) {
        setActiveReport(data.report);
        fetchStatus();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setScanning(false);
    }
  };

  const getCvssBadge = (score: number) => {
    if (score >= 9.0) return 'bg-rose-950 text-rose-400 border-rose-800';
    if (score >= 7.0) return 'bg-amber-950 text-amber-400 border-amber-800';
    if (score >= 4.0) return 'bg-yellow-950 text-yellow-400 border-yellow-800';
    return 'bg-cyan-950 text-cyan-400 border-cyan-800';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              OpenVAS / Greenbone Vulnerability Scanner
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 border border-rose-800 text-rose-300">
                GMP Engine
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Targeted CVE vulnerability scans, port auditing, compliance checks, and Greenbone reports.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {credentials && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                User: <strong>{credentials.username}</strong>
              </span>
            </div>
          )}
          <a
            href="https://openvas.vigilante.local"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 text-xs font-mono text-cyan-300 border border-cyan-800 transition-colors"
          >
            <span>GSA Web UI</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>

      {/* Cluster Status Banner */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div
            className={`w-3 h-3 rounded-full ${
              status?.ready ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'
            }`}
          />
          <div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              <span>GVM Daemon & Scanner Service</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                {status?.ready ? 'READY / OPERATIONAL' : 'INITIALIZING'}
              </span>
            </div>
            <div className="text-xs text-slate-400 font-mono pt-0.5">
              Namespace: <code>{status?.namespace || 'default'}</code> | Pods:{' '}
              {status?.pods?.length || 8} active
            </div>
          </div>
        </div>

        <button
          onClick={fetchStatus}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-400 border border-slate-800"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Health</span>
        </button>
      </div>

      {/* Scan Config Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="space-y-4 lg:col-span-1">
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Scan Target & Profile</span>
            </h2>

            {/* Target Select */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400">Target Host:</label>
              {discoveredHosts.length > 0 ? (
                <select
                  value={selectedHost}
                  onChange={(e) => setSelectedHost(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:outline-none"
                >
                  {discoveredHosts.map((h) => (
                    <option key={h.ip} value={h.ip}>
                      {h.ip} {h.hostname ? `(${h.hostname})` : ''} - {h.ports?.length || 0} ports
                    </option>
                  ))}
                </select>
              ) : null}
              <input
                type="text"
                placeholder="Or specify custom IP (e.g. 10.42.0.1)..."
                value={customHost}
                onChange={(e) => setCustomHost(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none"
              />
            </div>

            {/* Profile Select */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400">Scan Profile:</label>
              <div className="space-y-2">
                {profiles.map((prof) => (
                  <label
                    key={prof.id}
                    onClick={() => setSelectedProfile(prof.id)}
                    className={`block p-3 rounded-lg border cursor-pointer transition-all ${
                      selectedProfile === prof.id
                        ? 'bg-rose-950/40 border-rose-500/50 text-white'
                        : 'bg-slate-900/40 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-bold font-mono">
                      <span>{prof.name}</span>
                      <span className="text-[10px] text-cyan-400">{prof.estimatedDuration}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 pt-1 leading-snug">{prof.description}</p>
                  </label>
                ))}
              </div>
            </div>

            {/* Scan Button */}
            <button
              onClick={handleStartScan}
              disabled={scanning}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:bg-rose-900 text-white font-semibold text-xs transition-colors shadow-lg shadow-rose-900/20"
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Executing OpenVAS Scan...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Launch Vulnerability Scan</span>
                </>
              )}
            </button>
          </div>

          {/* Past Reports List */}
          {reports.length > 0 && (
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase">Saved Scan Reports</h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {reports.map((rep, idx) => (
                  <div
                    key={idx}
                    onClick={() => setActiveReport(rep)}
                    className={`p-2.5 rounded-lg border text-xs font-mono cursor-pointer flex items-center justify-between ${
                      activeReport === rep ? 'bg-cyan-950/40 border-cyan-500/50 text-white' : 'bg-slate-900/40 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div>
                      <div className="font-bold text-slate-200">{rep.targetHost || rep.host?.ip || 'Host'}</div>
                      <div className="text-[10px] text-slate-500">{rep.timestamp || 'Recent'}</div>
                    </div>
                    <span className="text-xs font-bold text-rose-400">{rep.findings?.length || 0} CVEs</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Results Area */}
        <div className="lg:col-span-2 space-y-4">
          {activeReport ? (
            <div className="space-y-4">
              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-center">
                  <div className="text-[10px] text-slate-500 uppercase">Target</div>
                  <div className="text-sm font-bold text-cyan-400 pt-0.5">{activeReport.targetHost || '127.0.0.1'}</div>
                </div>
                <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-center">
                  <div className="text-[10px] text-slate-500 uppercase">Profile</div>
                  <div className="text-sm font-bold text-white pt-0.5">{activeReport.profile || 'Full and Fast'}</div>
                </div>
                <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 font-mono text-center">
                  <div className="text-[10px] text-slate-500 uppercase">Total Findings</div>
                  <div className="text-sm font-bold text-rose-400 pt-0.5">{activeReport.findings?.length || 0}</div>
                </div>
              </div>

              {/* Findings Table */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
                <div className="p-3 bg-slate-900/80 border-b border-slate-800 text-xs font-mono text-slate-400 font-bold uppercase">
                  Identified Vulnerabilities & CVEs
                </div>
                <div className="divide-y divide-slate-800/60">
                  {(activeReport.findings || []).map((f: Finding, idx: number) => (
                    <div
                      key={idx}
                      onClick={() => setSelectedFinding(f)}
                      className="p-3.5 hover:bg-slate-900/40 cursor-pointer transition-colors flex items-start justify-between gap-4 font-mono text-xs"
                    >
                      <div className="space-y-1">
                        <div className="font-bold text-white flex items-center gap-2">
                          <span>{f.name}</span>
                          <span className={`text-[10px] px-2 py-0.2 rounded border ${getCvssBadge(f.cvss)}`}>
                            CVSS {f.cvss}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 line-clamp-1">{f.summary}</div>
                        <div className="text-[10px] text-slate-500 flex items-center gap-3">
                          <span>Port: {f.port || 'TCP'}</span>
                          <span>OID: {f.nvtOid || 'N/A'}</span>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-600 shrink-0 mt-1" />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-96 rounded-xl border border-slate-800 bg-slate-950/40 flex flex-col items-center justify-center text-center p-6 space-y-3 font-mono text-xs text-slate-500">
              <FileText className="w-8 h-8 text-slate-600" />
              <p>No vulnerability scan results loaded.</p>
              <p className="text-[11px] text-slate-600">
                Select a target on the left and click &quot;Launch Vulnerability Scan&quot; to audit against 85,000+ NVTs.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
