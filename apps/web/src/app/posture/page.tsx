'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  RefreshCw,
} from 'lucide-react';

interface KpsmViolation {
  ruleId?: string;
  title?: string;
  severity?: string;
  resource?: string;
  description?: string;
}

interface KspmScorecard {
  generatedAt?: string;
  overallScore?: number;
  grade?: string;
  workloadCount?: number;
  pssScore?: number;
  livePods?: boolean;
  cisFromAudit?: boolean;
  findings?: KpsmViolation[];
  topViolations?: KpsmViolation[];
  summary?: {
    pss?: { privileged?: number; baseline?: number; restricted?: number };
    cis?: { pass?: number; fail?: number; warn?: number; score?: number };
  };
}

export default function PosturePage() {
  const [activeTab, setActiveTab] = useState<'mitre' | 'cis' | 'remediation'>('mitre');
  const [scorecard, setScorecard] = useState<KspmScorecard | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPosture = () => {
    fetch('/api/posture')
      .then((res) => res.json())
      .then((d) => {
        if (d.success === false || !d.scorecard) {
          setError(d.error || 'Posture scorecard unavailable');
          setScorecard(null);
        } else {
          setError(null);
          setScorecard(d.scorecard);
        }
        setLoading(false);
      })
      .catch(() => {
        setError('Posture request failed');
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchPosture();
  }, []);

  const tactics = [
    { id: 'TA0001', name: 'Initial Access', techniques: ['T1190 Exploit Public-Facing App', 'T1078 Valid Accounts', 'T1566 Phishing'], coverage: 'HIGH' },
    { id: 'TA0002', name: 'Execution', techniques: ['T1059 Command & Scripting Interpreter', 'T1610 Deploy Container', 'T1204 User Execution'], coverage: 'HIGH' },
    { id: 'TA0003', name: 'Persistence', techniques: ['T1053 Scheduled Task/Cron', 'T1543 Create or Modify System Process'], coverage: 'MEDIUM' },
    { id: 'TA0004', name: 'Privilege Escalation', techniques: ['T1068 Exploitation for Priv Escalation', 'T1548 Abuse Elevation Control'], coverage: 'CRITICAL' },
    { id: 'TA0005', name: 'Defense Evasion', techniques: ['T1562 Impair Defenses', 'T1070 Indicator Removal'], coverage: 'MEDIUM' },
    { id: 'TA0006', name: 'Credential Access', techniques: ['T1003 OS Credential Dumping', 'T1552 Unsecured Credentials'], coverage: 'HIGH' },
    { id: 'TA0011', name: 'Command & Control', techniques: ['T1071 Application Layer Protocol', 'T1572 Protocol Tunneling (DNS)'], coverage: 'CRITICAL' }
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              KSPM Security Posture & MITRE ATT&CK Matrix
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                Continuous Compliance
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Evaluates Pod Security Standards (PSS), CIS Kubernetes Benchmarks, and adversary tactic coverage.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-mono">
          <button
            onClick={() => setActiveTab('mitre')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'mitre' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400'
            }`}
          >
            MITRE Matrix
          </button>
          <button
            onClick={() => setActiveTab('cis')}
            className={`px-3 py-1.5 rounded transition-colors ${
              activeTab === 'cis' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400'
            }`}
          >
            CIS Benchmark
          </button>
          <button
            onClick={fetchPosture}
            className="px-3 py-1.5 rounded transition-colors text-slate-400 hover:text-emerald-300 flex items-center gap-1"
            title="Refresh scorecard"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Grid */}
      {activeTab === 'mitre' && (
        <div className="rounded-2xl border border-slate-800 bg-[#070a13] p-6 space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-2 border-b border-slate-800">
            <span>Enterprise ATT&CK Matrix Coverage Heatmap</span>
            <span>Suricata + Falco + Zeek Sensor Ingestion</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {tactics.map((t) => (
              <div key={t.id} className="p-4 rounded-xl border border-slate-800 bg-slate-950 space-y-2.5 font-mono text-xs">
                <div className="flex items-center justify-between pb-1 border-b border-slate-900">
                  <span className="font-bold text-white text-[13px]">{t.name}</span>
                  <span className="text-[10px] text-cyan-400">{t.id}</span>
                </div>
                <div className="space-y-1.5">
                  {t.techniques.map((tech, i) => (
                    <div
                      key={i}
                      className="p-2 rounded bg-slate-900/70 border border-slate-800/80 text-[11px] text-slate-300 flex items-center justify-between"
                    >
                      <span className="truncate">{tech}</span>
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0"></span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CIS Benchmark Scorecard — live from /api/posture
          (generateKspmScorecard). The old cards were fully static:
          hardcoded "92% / 88% / 76%" plus invented claims about
          anonymous auth and kubelet ports, under a "Continuous
          Compliance" header, with no fetch at all. */}
      {activeTab === 'cis' && (
        <div className="space-y-6">
          {error && (
            <div className="p-3 rounded-xl border border-rose-800 bg-rose-950/40 text-rose-300 font-mono text-xs">
              Posture data unavailable: {error}
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-950 text-xs font-mono space-y-2">
              <span className="text-slate-500">Overall Posture</span>
              <div className="text-2xl font-bold text-white">
                {loading ? '…' : `${scorecard?.overallScore ?? '—'} / 100`}
                {scorecard?.grade && <span className="text-sm text-slate-400"> ({scorecard.grade})</span>}
              </div>
              <p className="text-[11px] text-slate-400">
                {loading ? 'Loading…' : `${scorecard?.workloadCount ?? '—'} workloads evaluated`}
              </p>
            </div>
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-950 text-xs font-mono space-y-2">
              <span className="text-slate-500">CIS Benchmark (Kube-bench)</span>
              <div className="text-2xl font-bold text-emerald-400">
                {loading ? '…' : `${scorecard?.summary?.cis?.score ?? '—'}% PASS`}
              </div>
              <p className="text-[11px] text-slate-400">
                {loading
                  ? 'Loading…'
                  : `Pass: ${scorecard?.summary?.cis?.pass ?? '—'} / Fail: ${scorecard?.summary?.cis?.fail ?? '—'} / Warn: ${scorecard?.summary?.cis?.warn ?? '—'}`}
              </p>
            </div>
            <div className="p-5 rounded-xl border border-slate-800 bg-slate-950 text-xs font-mono space-y-2">
              <span className="text-slate-500">Pod Security Standards (PSS)</span>
              <div className="text-2xl font-bold text-amber-400">
                {loading ? '…' : `${scorecard?.pssScore ?? '—'} / 100`}
              </div>
              <p className="text-[11px] text-slate-400">
                {loading
                  ? 'Loading…'
                  : `Privileged: ${scorecard?.summary?.pss?.privileged ?? '—'} / Baseline: ${scorecard?.summary?.pss?.baseline ?? '—'} / Restricted: ${scorecard?.summary?.pss?.restricted ?? '—'}`}
              </p>
            </div>
          </div>

          {/* Provenance: the scorecard falls back to sample workloads
              and default CIS counts when the cluster or saved audits
              are unavailable, so label sample data as such instead
              of presenting it as a live score. */}
          <p className="text-[11px] text-slate-500 font-mono">
            {loading
              ? 'Loading scorecard…'
              : `Source: ${scorecard?.livePods ? 'live cluster pods' : 'sample workloads — cluster unreachable'} · CIS: ${scorecard?.cisFromAudit ? 'saved kube-bench audit' : 'defaults — no saved audit'}${scorecard?.generatedAt ? ` · Generated ${new Date(scorecard.generatedAt).toLocaleString()}` : ''}`}
          </p>

          <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
            <div className="p-3 border-b border-slate-800 text-xs font-bold text-slate-300 bg-slate-900/40">
              Top Violations
            </div>
            <div className="divide-y divide-slate-800/60 font-mono text-xs">
              {loading ? (
                <div className="p-3 text-slate-500">Loading…</div>
              ) : (scorecard?.topViolations || []).length === 0 ? (
                <div className="p-3 text-slate-500">
                  {error ? 'No violations loaded.' : 'No violations found.'}
                </div>
              ) : (
                scorecard?.topViolations?.map((v, idx) => (
                  <div key={idx} className="p-3 flex items-center justify-between gap-3">
                    <span className="text-slate-400">
                      {v.ruleId ? `${v.ruleId}: ` : ''}{v.title || v.description || 'Violation'}
                      {v.resource ? ` (${v.resource})` : ''}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        v.severity === 'HIGH' || v.severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-400 border border-rose-800'
                          : 'bg-amber-950 text-amber-400 border border-amber-800'
                      }`}
                    >
                      {v.severity || '—'}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
