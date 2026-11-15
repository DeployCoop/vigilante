'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  Cpu,
  Play,
  RefreshCw,
  Server,
  Hash,
  Copy,
  Check,
} from 'lucide-react';

interface OobTarget {
  value: string;
  label: string;
}

interface OobProfile {
  id: string;
  name: string;
  description: string;
}

interface Bmc {
  ip: string;
  vendor?: string;
  firmware?: string;
  ipmiVersion?: string;
  hasRedfish?: boolean;
  cipherZero?: boolean;
}

interface OobScan {
  target?: string;
  timestamp?: string;
  bmcs?: Bmc[];
  parsed?: { bmcs?: Bmc[]; totalBmcs?: number; totalRakpHashes?: number };
  rakpHashes?: string[];
}

interface OobData {
  targets: OobTarget[];
  profiles: OobProfile[];
  scans: OobScan[];
}

export default function OobscanPage() {
  const [data, setData] = useState<OobData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [scanning, setScanning] = useState<boolean>(false);
  const [selectedTarget, setSelectedTarget] = useState<string>('127.0.0.1');
  const [customTarget, setCustomTarget] = useState<string>('');
  const [selectedProfile, setSelectedProfile] = useState<string>('standard');
  const [activeScan, setActiveScan] = useState<OobScan | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchOobData = useCallback(() => {
    fetch('/api/oobscan')
      .then((res) => res.json())
      .then((d) => {
        setData(d);
        if (d.scans?.length > 0) {
          setActiveScan((prev) => prev ?? d.scans[0]);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    fetchOobData();
  }, [fetchOobData]);

  const handleStartScan = async () => {
    const target = customTarget.trim() || selectedTarget;
    setScanning(true);
    try {
      const res = await fetch('/api/oobscan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, profile: selectedProfile })
      });
      const result = await res.json();
      if (result.success) {
        fetchOobData();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setScanning(false);
    }
  };

  const targets = data?.targets || [];
  const profiles = data?.profiles || [];
  const scans = data?.scans || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              OOBscan BMC & Hardware Security Audit
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 border border-amber-800 text-amber-300">
                IPMI / Redfish
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Audit Out-of-Band BMC hardware (iLO, iDRAC, IPMI v1.5/2.0), capture RAKP hashes, and sweep link-local subnets.
            </p>
          </div>
        </div>

        <button
          onClick={() => {
              setLoading(true);
              fetchOobData();
            }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Controls Column */}
        <div className="space-y-4 lg:col-span-1">
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-400" />
              <span>Target & Profiles</span>
            </h2>

            {/* Target Selector */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400">Target Segment:</label>
              {targets.length > 0 && (
                <select
                  value={selectedTarget}
                  onChange={(e) => setSelectedTarget(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 focus:outline-none"
                >
                  {targets.map((t, i: number) => (
                    <option key={i} value={t.value}>
                      {t.label} ({t.value})
                    </option>
                  ))}
                </select>
              )}
              <input
                type="text"
                placeholder="Or custom IP/CIDR (e.g. 192.168.1.0/24)..."
                value={customTarget}
                onChange={(e) => setCustomTarget(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none"
              />
            </div>

            {/* Profile Selector */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400">Audit Profile:</label>
              <div className="space-y-2">
                {profiles.map((p) => (
                  <label
                    key={p.id}
                    onClick={() => setSelectedProfile(p.id)}
                    className={`block p-3 rounded-lg border cursor-pointer transition-all ${
                      selectedProfile === p.id
                        ? 'bg-amber-950/40 border-amber-500/50 text-white'
                        : 'bg-slate-900/40 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <div className="text-xs font-bold font-mono">{p.name}</div>
                    <div className="text-[11px] text-slate-400 pt-1 leading-snug">{p.description}</div>
                  </label>
                ))}
              </div>
            </div>

            {/* Launch Scan */}
            <button
              onClick={handleStartScan}
              disabled={scanning}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:bg-amber-900 text-slate-950 font-semibold text-xs transition-colors shadow-lg shadow-amber-900/20 font-mono"
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Sweeping BMC Network...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Start BMC Hardware Audit</span>
                </>
              )}
            </button>
          </div>

          {/* Past Scans List */}
          {scans.length > 0 && (
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase">Captured OOB Scans</h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {scans.map((s, idx: number) => (
                  <div
                    key={idx}
                    onClick={() => setActiveScan(s)}
                    className={`p-2.5 rounded-lg border text-xs font-mono cursor-pointer flex items-center justify-between ${
                      activeScan === s ? 'bg-amber-950/40 border-amber-500/50 text-white' : 'bg-slate-900/40 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div>
                      <div className="font-bold text-slate-200">{s.target || 'Subnet'}</div>
                      <div className="text-[10px] text-slate-500">{s.timestamp || 'Recent'}</div>
                    </div>
                    <span className="text-xs font-bold text-amber-400">
                      {s.parsed?.totalBmcs || s.bmcs?.length || 0} BMCs
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Display / Telemetry Column */}
        <div className="lg:col-span-2 space-y-4">
          {activeScan ? (
            <div className="space-y-4">
              {/* Scan Stats */}
              <div className="grid grid-cols-3 gap-3 font-mono">
                <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 text-center">
                  <div className="text-[10px] text-slate-500 uppercase">Target</div>
                  <div className="text-sm font-bold text-amber-400 pt-0.5">{activeScan.target || '127.0.0.1'}</div>
                </div>
                <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 text-center">
                  <div className="text-[10px] text-slate-500 uppercase">BMCs Identified</div>
                  <div className="text-sm font-bold text-white pt-0.5">
                    {activeScan.parsed?.totalBmcs || activeScan.bmcs?.length || 0}
                  </div>
                </div>
                <div className="p-3 rounded-xl border border-slate-800 bg-slate-950/60 text-center">
                  <div className="text-[10px] text-slate-500 uppercase">RAKP Hashes</div>
                  <div className="text-sm font-bold text-rose-400 pt-0.5">
                    {activeScan.parsed?.totalRakpHashes || activeScan.rakpHashes?.length || 0}
                  </div>
                </div>
              </div>

              {/* BMC Details Table */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden font-mono text-xs">
                <div className="p-3 bg-slate-900/80 border-b border-slate-800 text-slate-400 font-bold uppercase flex items-center justify-between">
                  <span>Discovered Baseboard Management Controllers</span>
                  <span className="text-[10px] text-amber-400">IPMI v1.5 / v2.0 & Redfish</span>
                </div>
                <div className="divide-y divide-slate-800/60">
                  {(activeScan.bmcs || activeScan.parsed?.bmcs || []).length === 0 ? (
                    <div className="p-6 text-center text-slate-500">
                      No BMC devices detected on the specified subnet.
                    </div>
                  ) : (
                    (activeScan.bmcs || activeScan.parsed?.bmcs || []).map((bmc, idx: number) => (
                      <div key={idx} className="p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-white font-bold text-sm">{bmc.ip}</span>
                          <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px]">
                            {bmc.vendor || 'Generic IPMI'}
                          </span>
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-slate-400 pt-1">
                          <div>Firmware: <span className="text-slate-200">{bmc.firmware || '1.0'}</span></div>
                          <div>IPMI: <span className="text-slate-200">{bmc.ipmiVersion || 'v2.0'}</span></div>
                          <div>Redfish: <span className="text-slate-200">{bmc.hasRedfish ? 'Supported' : 'No'}</span></div>
                          <div>Cipher Suite 0: <span className="text-rose-400 font-bold">{bmc.cipherZero ? 'VULNERABLE' : 'Safe'}</span></div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* RAKP Hashes Section */}
              <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-rose-400 font-bold">
                    <Hash className="w-4 h-4" />
                    <span>Captured RAKP HMAC Hashes (Offline Cracking)</span>
                  </div>
                  <button
                    onClick={() => {
                      const hashText = (activeScan.rakpHashes || []).join('\n');
                      navigator.clipboard.writeText(hashText);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                    className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[11px]"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy Hashes'}</span>
                  </button>
                </div>
                <div className="bg-black/60 p-3 rounded-lg border border-slate-900 text-slate-400 text-[11px] max-h-32 overflow-y-auto whitespace-pre">
                  {(activeScan.rakpHashes || []).length > 0
                    ? activeScan.rakpHashes.join('\n')
                    : 'No RAKP hashes captured in this scan.'}
                </div>
              </div>
            </div>
          ) : (
            <div className="h-96 rounded-xl border border-slate-800 bg-slate-950/40 flex flex-col items-center justify-center text-center p-6 space-y-3 font-mono text-xs text-slate-500">
              <Cpu className="w-8 h-8 text-slate-600" />
              <p>No OOB BMC scan selected.</p>
              <p className="text-[11px] text-slate-600">
                Choose a subnet target on the left and start an audit to enumerate IPMI, iLO, and iDRAC controllers.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
