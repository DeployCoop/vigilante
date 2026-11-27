'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  Bot,
  ShieldCheck,
  ShieldAlert,
  Play,
  Trash2,
  RotateCcw,
  Flag,
  FileCode,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Search,
  Lock,
  Layers,
  Terminal,
  Swords,
  Copy,
  Check,
  Server
} from 'lucide-react';

interface Scenario {
  id: string;
  stackDir: string;
  name: string;
  kind: 'target' | 'arsenal';
  difficulty: string;
  port: number;
  owaspLlm: string[];
  mitreAtlas: string[];
  description: string;
  hints: string[];
  recommendedFalcoRules: string[];
  telemetry?: {
    falcoScenario: string;
    suricataSignature: string;
    recommendedSoar: string;
    purpleObjective: string;
  };
}

interface BridgedRecord {
  id: string;
  challengeId: string;
  scenarioId: string;
  scenarioName: string;
  kind: string;
  teamId: string;
  namespace: string;
  port: number;
  rangeUiUrl: string;
  scenarioEndpoint: string;
  owaspLlm: string[];
  mitreAtlas: string[];
  status: string;
  synthetic: boolean;
  runner: string;
  createdAt: string;
}

export default function RedAiRangePage() {
  const [activeTab, setActiveTab] = useState<'scenarios' | 'bridge' | 'validator'>('scenarios');

  // Status state
  const [statusData, setStatusData] = useState<any>(null);
  const [statusLoading, setStatusLoading] = useState<boolean>(true);
  const [deployLoading, setDeployLoading] = useState<boolean>(false);
  const [actionBanner, setActionBanner] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // Scenarios state
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [kindFilter, setKindFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [previewCompose, setPreviewCompose] = useState<{ scenarioId: string; yaml: string } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Bridge state
  const [bridged, setBridged] = useState<BridgedRecord[]>([]);
  const [teamId, setTeamId] = useState<string>('web-operative');
  const [bridgeLoadingId, setBridgeLoadingId] = useState<string | null>(null);
  const [flagInputs, setFlagInputs] = useState<Record<string, string>>({});
  const [flagResults, setFlagResults] = useState<Record<string, { ok: boolean; message: string }>>({});

  // Validator state
  const [composeYaml, setComposeYaml] = useState<string>(
`services:
  custom_llm_target:
    image: python:3.11-slim
    container_name: rar-custom-llm
    ports:
      - "127.0.0.1:11009:8000"
    security_opt:
      - no-new-privileges:true
    command: ["python3", "-m", "http.server", "8000"]`
  );
  const [validationResult, setValidationResult] = useState<any>(null);
  const [validating, setValidating] = useState<boolean>(false);

  const fetchAll = useCallback(async () => {
    setStatusLoading(true);
    try {
      const [stRes, scRes, brRes] = await Promise.all([
        fetch('/api/redairange/status').then((r) => r.json()).catch(() => null),
        fetch('/api/redairange/scenarios').then((r) => r.json()).catch(() => null),
        fetch('/api/redairange/bridge').then((r) => r.json()).catch(() => null)
      ]);
      if (stRes?.success) setStatusData(stRes);
      if (scRes?.success) setScenarios(scRes.scenarios || []);
      if (brRes?.success) setBridged(brRes.bridged || []);
    } finally {
      setStatusLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchAll();
  }, [fetchAll]);

  const handleModuleAction = async (action: 'install' | 'uninstall') => {
    setDeployLoading(true);
    setActionBanner(null);
    try {
      const res = await fetch('/api/modules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, moduleId: 'redairange', namespace: 'redairange' })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setActionBanner({
          kind: 'ok',
          text: action === 'install'
            ? 'RedAiRange module deployed with isolated DinD sidecar (namespace: redairange).'
            : 'RedAiRange module uninstalled cleanly.'
        });
        await fetchAll();
      } else {
        setActionBanner({ kind: 'err', text: data.error || `Failed to ${action} RedAiRange module.` });
      }
    } catch (err: any) {
      setActionBanner({ kind: 'err', text: err?.message || 'Request failed' });
    } finally {
      setDeployLoading(false);
    }
  };

  const handlePreviewCompose = async (scenarioId: string) => {
    try {
      const res = await fetch('/api/redairange/scenarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'generate', scenarioId })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setPreviewCompose({ scenarioId, yaml: data.composeYaml });
      } else {
        setActionBanner({ kind: 'err', text: data.error || 'Could not generate compose stack' });
      }
    } catch (err: any) {
      setActionBanner({ kind: 'err', text: err?.message || 'Could not generate compose stack' });
    }
  };

  const handleBridgeScenario = async (scenarioId: string) => {
    setBridgeLoadingId(scenarioId);
    setActionBanner(null);
    try {
      const res = await fetch('/api/redairange/bridge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId, teamId })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setActionBanner({
          kind: 'ok',
          text: `Bridged '${scenarioId}' into AI-CTF as ${data.bridge?.challengeId} (${data.bridge?.synthetic ? 'simulated fallback — cluster pod offline' : 'provisioned in DinD /opt/stacks'}).`
        });
        await fetchAll();
        setActiveTab('bridge');
      } else {
        setActionBanner({ kind: 'err', text: data.error || 'Failed to bridge scenario to AI-CTF' });
      }
    } catch (err: any) {
      setActionBanner({ kind: 'err', text: err?.message || 'Bridge request failed' });
    } finally {
      setBridgeLoadingId(null);
    }
  };

  const handleTeardownBridge = async (bridgeId: string) => {
    try {
      const res = await fetch(`/api/redairange/bridge?bridgeId=${encodeURIComponent(bridgeId)}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setActionBanner({ kind: 'ok', text: `Removed bridged challenge '${bridgeId}'.` });
        await fetchAll();
      } else {
        setActionBanner({ kind: 'err', text: data.error || 'Teardown failed' });
      }
    } catch (err: any) {
      setActionBanner({ kind: 'err', text: err?.message || 'Teardown failed' });
    }
  };

  const handleSubmitFlag = async (challengeId: string, bridgeTeamId: string) => {
    const flag = (flagInputs[challengeId] || '').trim();
    if (!flag) return;
    try {
      const res = await fetch('/api/ctf/challenges', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId, teamId: bridgeTeamId, flag })
      });
      const data = await res.json();
      setFlagResults((prev) => ({
        ...prev,
        [challengeId]: {
          ok: Boolean(data.success),
          message: data.success
            ? `Accepted! +${data.pointsAwarded || 0} pts ${data.bloodBadge || ''}`
            : (data.reason || data.error || 'Rejected by fail-closed HMAC verifier')
        }
      }));
    } catch (err: any) {
      setFlagResults((prev) => ({
        ...prev,
        [challengeId]: { ok: false, message: err?.message || 'Submission failed' }
      }));
    }
  };

  const handleValidateCompose = async () => {
    setValidating(true);
    setValidationResult(null);
    try {
      const res = await fetch('/api/redairange/scenarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'validate', rawYaml: composeYaml })
      });
      const data = await res.json();
      setValidationResult(data);
    } catch (err: any) {
      setValidationResult({ valid: false, errors: [err?.message || 'Validation failed'], warnings: [] });
    } finally {
      setValidating(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const filteredScenarios = scenarios.filter((s) => {
    if (kindFilter !== 'all' && s.kind !== kindFilter) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      s.id.includes(q) ||
      s.name.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.owaspLlm.some((o) => o.toLowerCase().includes(q)) ||
      s.mitreAtlas.some((m) => m.toLowerCase().includes(q))
    );
  });

  const isInstalled = Boolean(statusData?.status?.installed);
  const webConsoleUrl = statusData?.status?.endpoints?.[0]?.url || `https://redairange.${statusData?.domain || 'vigilante.local'}`;

  return (
    <div className="space-y-6 font-mono pb-16">
      {/* Header */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex flex-wrap items-center gap-2">
              RedAiRange AI Red-Teaming Cyber Range
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                Isolated DinD · Zero Host docker.sock
              </span>
              <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 border border-rose-800 text-rose-300">
                OWASP LLM · MITRE ATLAS
              </span>
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Containerized AI/ML vulnerability labs, adversarial playgrounds, Blackcart arsenal & fail-closed AI-CTF bridge on k3d/k3s.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <a
            href={webConsoleUrl}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-cyan-300 transition-colors"
          >
            <ExternalLink className="w-3.5 h-3.5" />
            <span>Range UI (:5002)</span>
          </a>
          <button
            onClick={() => handleModuleAction(isInstalled ? 'uninstall' : 'install')}
            disabled={deployLoading}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition-colors border ${
              isInstalled
                ? 'bg-rose-950/70 hover:bg-rose-900/70 border-rose-700 text-rose-200'
                : 'bg-cyan-600 hover:bg-cyan-500 border-cyan-400 text-slate-950'
            }`}
          >
            {isInstalled ? <Trash2 className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{deployLoading ? 'Working...' : isInstalled ? 'Uninstall Module' : 'Deploy Isolated Range'}</span>
          </button>
          <button
            onClick={() => void fetchAll()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-colors"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${statusLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {actionBanner && (
        <div
          className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
            actionBanner.kind === 'ok'
              ? 'bg-emerald-950/50 border-emerald-800 text-emerald-300'
              : 'bg-rose-950/50 border-rose-800 text-rose-300'
          }`}
        >
          {actionBanner.kind === 'ok' ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertTriangle className="w-4 h-4 shrink-0" />}
          <span>{actionBanner.text}</span>
        </div>
      )}

      {/* Telemetry & Isolation Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>Cluster Deployment</span>
            <Server className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-base font-bold text-white flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${isInstalled ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
            <span>{statusData?.status?.status || 'Not Installed'}</span>
          </div>
          <p className="text-[11px] text-slate-500">
            ns: {statusData?.status?.namespace || 'redairange'} · {statusData?.clusterName || 'vigilante-dev'}
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>Runtime Isolation</span>
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-base font-bold text-emerald-300">
            Pod-Private DinD
          </div>
          <p className="text-[11px] text-slate-500">
            unix:///var/run/dind/docker.sock · k3d &amp; k3s
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>AI Scenarios &amp; Arsenal</span>
            <Layers className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-base font-bold text-white">
            {scenarios.length || 7} Pre-Seeded Stacks
          </div>
          <p className="text-[11px] text-slate-500">
            Targets + Blackcart CART Arsenal (/opt/stacks)
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>AI-CTF Bridge</span>
            <Flag className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-base font-bold text-amber-300">
            {bridged.length} Active Bridged
          </div>
          <p className="text-[11px] text-slate-500">
            Fail-closed HMAC-SHA256 per-team flags ·{' '}
            <Link href="/ctf" className="text-cyan-400 underline">
              CTF Arena
            </Link>
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 pb-1">
        <button
          onClick={() => setActiveTab('scenarios')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-bold transition-all border-b-2 ${
            activeTab === 'scenarios'
              ? 'bg-slate-900 text-cyan-300 border-cyan-400'
              : 'text-slate-400 hover:text-slate-200 border-transparent'
          }`}
        >
          <Swords className="w-3.5 h-3.5" />
          <span>AI Scenarios &amp; Arsenal ({scenarios.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('bridge')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-bold transition-all border-b-2 ${
            activeTab === 'bridge'
              ? 'bg-slate-900 text-amber-300 border-amber-400'
              : 'text-slate-400 hover:text-slate-200 border-transparent'
          }`}
        >
          <Flag className="w-3.5 h-3.5" />
          <span>AI-CTF Bridge ({bridged.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('validator')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-bold transition-all border-b-2 ${
            activeTab === 'validator'
              ? 'bg-slate-900 text-emerald-300 border-emerald-400'
              : 'text-slate-400 hover:text-slate-200 border-transparent'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Stack Linter &amp; Purple-Team Telemetry</span>
        </button>
      </div>

      {/* TAB 1: Scenarios */}
      {activeTab === 'scenarios' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              {(['all', 'target', 'arsenal'] as const).map((k) => (
                <button
                  key={k}
                  onClick={() => setKindFilter(k)}
                  className={`px-3 py-1.5 rounded-lg text-xs border transition-colors ${
                    kindFilter === k
                      ? 'bg-cyan-950/70 border-cyan-700 text-cyan-300 font-bold'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  {k === 'all' ? 'All Stacks' : k === 'target' ? 'Vulnerable AI Targets' : 'Red-Team Arsenal'}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Filter by OWASP, ATLAS, name..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-600 w-64"
                />
              </div>
              <input
                type="text"
                value={teamId}
                onChange={(e) => setTeamId(e.target.value)}
                title="Target teamId for AI-CTF bridging"
                placeholder="Team ID"
                className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-amber-300 focus:outline-none focus:border-amber-600 w-36"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {filteredScenarios.map((s) => (
              <div
                key={s.id}
                className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-colors flex flex-col justify-between gap-4"
              >
                <div className="space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <span>{s.name}</span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded uppercase border ${
                            s.kind === 'target'
                              ? 'bg-rose-950/70 border-rose-800 text-rose-300'
                              : 'bg-purple-950/70 border-purple-800 text-purple-300'
                          }`}
                        >
                          {s.kind}
                        </span>
                      </h3>
                      <div className="text-[11px] text-slate-500 mt-0.5">
                        /opt/stacks/{s.stackDir} · port :{s.port} · {s.difficulty}
                      </div>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">{s.description}</p>

                  <div className="flex flex-wrap gap-1.5">
                    {s.owaspLlm.map((tag) => (
                      <span
                        key={tag}
                        className="text-[10px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-300"
                      >
                        {tag}
                      </span>
                    ))}
                    {s.mitreAtlas.map((t) => (
                      <span
                        key={t}
                        className="text-[10px] px-2 py-0.5 rounded bg-amber-950/40 border border-amber-900/60 text-amber-300"
                      >
                        {t}
                      </span>
                    ))}
                  </div>

                  {s.telemetry && (
                    <div className="text-[11px] text-slate-400 bg-slate-950/60 border border-slate-800/80 rounded-lg p-2.5 space-y-1">
                      <div className="text-emerald-400 font-semibold">
                        Purple-Team Telemetry · SOAR: {s.telemetry.recommendedSoar}
                      </div>
                      <div>Falco: {s.recommendedFalcoRules.join(', ')}</div>
                      <div className="text-slate-500">{s.telemetry.purpleObjective}</div>
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/80">
                  <button
                    onClick={() => void handlePreviewCompose(s.id)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition-colors"
                  >
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Inspect Stack YAML</span>
                  </button>

                  <button
                    onClick={() => void handleBridgeScenario(s.id)}
                    disabled={bridgeLoadingId === s.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-xs font-bold text-amber-300 transition-colors"
                  >
                    <Flag className="w-3.5 h-3.5" />
                    <span>{bridgeLoadingId === s.id ? 'Bridging...' : 'Bridge to AI-CTF'}</span>
                  </button>
                </div>
              </div>
            ))}
          </div>

          {previewCompose && (
            <div className="p-4 rounded-xl bg-slate-950 border border-cyan-800/60 space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-xs font-bold text-cyan-300 flex items-center gap-2">
                  <Terminal className="w-4 h-4" />
                  <span>Hardened compose.yaml — {previewCompose.scenarioId}</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy(previewCompose.yaml, 'preview')}
                    className="flex items-center gap-1 px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-300 hover:text-white"
                  >
                    {copiedKey === 'preview' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'preview' ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={() => setPreviewCompose(null)}
                    className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-400 hover:text-white"
                  >
                    Close
                  </button>
                </div>
              </div>
              <pre className="text-[11px] text-slate-300 overflow-x-auto p-3 rounded-lg bg-slate-900/70 border border-slate-800">
                {previewCompose.yaml}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: AI-CTF Bridge */}
      {activeTab === 'bridge' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Flag className="w-4 h-4 text-amber-400" />
                <span>Fail-Closed AI-CTF Tournament Bridge</span>
              </h2>
              <p className="text-xs text-slate-400">
                Every bridged RedAiRange stack injects an HMAC-SHA256 flag derived from <code className="text-cyan-300">VIGILANTE_CTF_SECRET</code> and registers directly in the kCTF Tournament Engine. Flags are never returned over API responses.
              </p>
            </div>
            <Link
              href="/ctf"
              className="px-3 py-1.5 rounded-lg bg-cyan-950/70 hover:bg-cyan-900/70 border border-cyan-800 text-xs text-cyan-300 font-bold shrink-0"
            >
              Open kCTF Arena →
            </Link>
          </div>

          {bridged.length === 0 ? (
            <div className="p-10 text-center rounded-xl bg-slate-900/40 border border-slate-800 border-dashed text-xs text-slate-500 space-y-2">
              <p>No RedAiRange scenarios have been bridged to AI-CTF yet.</p>
              <p>Select any scenario in the Scenarios tab and click <strong>Bridge to AI-CTF</strong> (requires <code>VIGILANTE_CTF_SECRET</code>).</p>
            </div>
          ) : (
            <div className="space-y-3">
              {bridged.map((rec) => {
                const subRes = flagResults[rec.challengeId];
                return (
                  <div
                    key={rec.id}
                    className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3"
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                      <div>
                        <div className="text-sm font-bold text-white flex flex-wrap items-center gap-2">
                          <span>{rec.scenarioName}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                            {rec.challengeId}
                          </span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-amber-300">
                            team: {rec.teamId}
                          </span>
                          {rec.synthetic && (
                            <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/70 border border-amber-800 text-amber-300">
                              synthetic · runner: {rec.runner}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-500 mt-1">
                          Endpoint: <code className="text-slate-300">{rec.scenarioEndpoint}</code> · Console:{' '}
                          <a href={rec.rangeUiUrl} target="_blank" rel="noreferrer" className="text-cyan-400 underline">
                            {rec.rangeUiUrl}
                          </a>
                        </div>
                      </div>

                      <button
                        onClick={() => void handleTeardownBridge(rec.id)}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-rose-950/60 hover:bg-rose-900/60 border border-rose-800 text-xs text-rose-300 self-start"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>Teardown</span>
                      </button>
                    </div>

                    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                      <input
                        type="text"
                        placeholder="VIGILANTE{ai-...}"
                        value={flagInputs[rec.challengeId] || ''}
                        onChange={(e) =>
                          setFlagInputs((prev) => ({ ...prev, [rec.challengeId]: e.target.value }))
                        }
                        className="flex-1 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-600"
                      />
                      <button
                        onClick={() => void handleSubmitFlag(rec.challengeId, rec.teamId)}
                        className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-bold transition-colors"
                      >
                        Verify &amp; Score Flag
                      </button>
                    </div>

                    {subRes && (
                      <div
                        className={`text-xs px-3 py-1.5 rounded border ${
                          subRes.ok
                            ? 'bg-emerald-950/50 border-emerald-800 text-emerald-300'
                            : 'bg-rose-950/50 border-rose-800 text-rose-300'
                        }`}
                      >
                        {subRes.message}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Stack Linter & Telemetry */}
      {activeTab === 'validator' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Scenario compose.yaml Security Linter</span>
              </h3>
              <button
                onClick={() => void handleValidateCompose()}
                disabled={validating}
                className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-bold transition-colors"
              >
                {validating ? 'Validating...' : 'Validate Stack'}
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              Enforces Vigilante isolation guardrails: blocks host <code>/var/run/docker.sock</code> mounts, <code>privileged: true</code>, host PID/network modes, and <code>..</code> volume traversal.
            </p>
            <textarea
              value={composeYaml}
              onChange={(e) => setComposeYaml(e.target.value)}
              rows={12}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-600 font-mono"
            />
            {validationResult && (
              <div
                className={`p-3 rounded-lg border text-xs space-y-1.5 ${
                  validationResult.valid
                    ? 'bg-emerald-950/50 border-emerald-800 text-emerald-300'
                    : 'bg-rose-950/50 border-rose-800 text-rose-300'
                }`}
              >
                <div className="font-bold flex items-center gap-2">
                  {validationResult.valid ? (
                    <CheckCircle2 className="w-4 h-4" />
                  ) : (
                    <ShieldAlert className="w-4 h-4" />
                  )}
                  <span>{validationResult.valid ? 'Stack passed isolation checks' : 'Stack rejected by security policy'}</span>
                </div>
                {(validationResult.errors || []).map((e: string, idx: number) => (
                  <div key={idx}>• {e}</div>
                ))}
                {(validationResult.warnings || []).map((w: string, idx: number) => (
                  <div key={idx} className="text-amber-300">⚠ {w}</div>
                ))}
              </div>
            )}
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <span>Purple-Team Detection Matrix (Falco + MITRE ATLAS)</span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Correlate RedAiRange AI attacks with Vigilante&apos;s eBPF Falco runtime sensor, Suricata signatures, and automated SOAR containment playbooks.
            </p>
            <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
              {scenarios.map((s) => (
                <div key={s.id} className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-bold text-slate-200">{s.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300">
                      {s.telemetry?.recommendedSoar || 'ALERT_ONLY'}
                    </span>
                  </div>
                  <div className="text-[11px] text-cyan-400">
                    ATLAS: {s.mitreAtlas.join(', ')}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Suricata: {s.telemetry?.suricataSignature}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Falco Rules: {s.recommendedFalcoRules.join(' · ')}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
