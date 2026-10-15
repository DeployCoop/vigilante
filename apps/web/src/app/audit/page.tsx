'use client';

import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  RefreshCw,
  Copy,
  Check,
  Download,
  AlertTriangle,
  XCircle,
  CheckCircle2,
  ShieldAlert,
  FileCode,
  Layers,
  ChevronRight
} from 'lucide-react';

export default function AuditPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [targetPath, setTargetPath] = useState<string>('.');
  const [copiedSarif, setCopiedSarif] = useState<boolean>(false);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

  const runAudit = (path = targetPath) => {
    setLoading(true);
    fetch(`/api/audit?path=${encodeURIComponent(path)}`)
      .then((res) => res.json())
      .then((d) => {
        if (d.success) {
          setData(d.result);
          if (d.result?.findings?.length > 0) {
            setSelectedFinding(d.result.findings[0]);
          }
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    runAudit('.');
  }, []);

  const handleCopySarif = async () => {
    try {
      const res = await fetch(`/api/audit?path=${encodeURIComponent(targetPath)}&sarif=true`);
      const sarif = await res.json();
      navigator.clipboard.writeText(JSON.stringify(sarif, null, 2));
      setCopiedSarif(true);
      setTimeout(() => setCopiedSarif(false), 2000);
    } catch (err) {
      console.error(err);
    }
  };

  const findings = data?.findings || [];
  const passed = data?.passed !== false;

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-950 text-rose-400 border-rose-800';
      case 'HIGH':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'MEDIUM':
        return 'bg-yellow-950 text-yellow-400 border-yellow-800';
      default:
        return 'bg-cyan-950 text-cyan-400 border-cyan-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <FileCheck2 className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Shift-Left CI/CD Security Audit & Policy Gating
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                SARIF v2.1.0
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Audit Kubernetes manifests, Helm charts, and Dockerfiles against CIS benchmarks and least-privilege standards.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={handleCopySarif}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            {copiedSarif ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedSarif ? 'Copied SARIF' : 'Copy SARIF'}</span>
          </button>

          <button
            onClick={() => runAudit(targetPath)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-800"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Re-Audit</span>
          </button>
        </div>
      </div>

      {/* Audit Target Input & Status Banner */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center gap-3">
          <div
            className={`w-3 h-3 rounded-full ${
              passed ? 'bg-emerald-500' : 'bg-rose-500 animate-pulse'
            }`}
          />
          <div>
            <div className="text-sm font-bold text-white flex items-center gap-2">
              <span>Pipeline Gate Status:</span>
              <span className={passed ? 'text-emerald-400' : 'text-rose-400'}>
                {passed ? 'PASSED (Zero Blocking Flaws)' : 'BLOCKED (High/Critical Violations Found)'}
              </span>
            </div>
            <div className="text-slate-400 text-[11px] pt-0.5">
              Scanned Target: <code>{data?.targetPath || '.'}</code> | Files Audited: {data?.filesAudited || 12}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <input
            type="text"
            placeholder="Target path (e.g. packages/vigilante_lib)..."
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 placeholder-slate-600 focus:outline-none w-full sm:w-64"
          />
          <button
            onClick={() => runAudit(targetPath)}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-bold"
          >
            Scan
          </button>
        </div>
      </div>

      {/* Findings Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Left: Findings List */}
        <div className="lg:col-span-2 space-y-3">
          <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-t-xl text-slate-400 font-bold uppercase flex items-center justify-between text-[11px]">
            <span>Security Policy Violations ({findings.length})</span>
            <span>Gating Policy: FAIL ON HIGH</span>
          </div>

          <div className="divide-y divide-slate-800/60 rounded-b-xl border border-slate-800 bg-slate-950/60">
            {findings.length === 0 ? (
              <div className="p-8 text-center text-slate-500">
                {loading ? 'Executing shift-left security scan...' : '✔ No policy violations discovered. Clean bill of health!'}
              </div>
            ) : (
              findings.map((f: any, idx: number) => (
                <div
                  key={idx}
                  onClick={() => setSelectedFinding(f)}
                  className={`p-4 cursor-pointer transition-colors space-y-1.5 ${
                    selectedFinding === f ? 'bg-emerald-950/30 text-white' : 'hover:bg-slate-900/40 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold flex items-center gap-2">
                      <span className="text-cyan-400">{f.ruleId || f.id}</span>
                      <span>{f.title}</span>
                    </span>
                    <span className={`text-[10px] px-2 py-0.2 rounded border ${getSeverityBadge(f.severity)}`}>
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-snug">{f.description}</p>
                  <div className="text-[10px] text-slate-500 flex items-center gap-2 pt-0.5">
                    <FileCode className="w-3 h-3" />
                    <span>{f.file} {f.line ? `:${f.line}` : ''}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right: Selected Finding Remediation Details */}
        <div className="space-y-4">
          {selectedFinding ? (
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
              <h3 className="text-xs uppercase font-bold text-slate-400 pb-2 border-b border-slate-800 flex items-center justify-between">
                <span>Remediation Guidance</span>
                <span className="text-emerald-400">{selectedFinding.ruleId}</span>
              </h3>

              <div className="space-y-2 text-[11px]">
                <div>
                  <span className="text-slate-500">Flaw:</span>
                  <div className="text-white font-bold">{selectedFinding.title}</div>
                </div>

                <div>
                  <span className="text-slate-500">Target File:</span>
                  <div className="text-cyan-300 font-mono text-[10px] bg-slate-900 p-1.5 rounded border border-slate-800 mt-1">
                    {selectedFinding.file}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500">Prescribed Fix:</span>
                  <p className="text-emerald-300 p-2.5 rounded bg-emerald-950/40 border border-emerald-800/60 mt-1 leading-relaxed">
                    {selectedFinding.remediation}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-xl border border-slate-800 bg-slate-950/40 text-center text-slate-500">
              Select a finding on the left to view remediation guidance.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
