'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  ShieldAlert,
  Terminal,
  Activity,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Flame,
  Cpu,
  Layers,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Shield,
  Zap,
  Check,
  Copy
} from 'lucide-react';

export default function FalcoDashboardPage() {
  const [activeTab, setActiveTab] = useState<'rules' | 'simulator' | 'validator'>('rules');
  
  // Status state
  const [status, setStatus] = useState<any>(null);
  const [statusLoading, setStatusLoading] = useState<boolean>(true);

  // Rules state
  const [rules, setRules] = useState<any[]>([]);
  const [rulesLoading, setRulesLoading] = useState<boolean>(true);
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [expandedRule, setExpandedRule] = useState<string | null>(null);

  // Simulator state
  const [selectedScenario, setSelectedScenario] = useState<string>('shell-spawn');
  const [simLoading, setSimLoading] = useState<boolean>(false);
  const [simResult, setSimResult] = useState<any>(null);

  // Validator state
  const [ruleYaml, setRuleYaml] = useState<string>(
`- rule: Unauthorized Process in Container
  desc: Detects unexpected process execution in application pod
  condition: container and proc.name in (nc, ncat, netcat, nmap)
  output: "Unauthorized process spawned (proc=%proc.name container=%container.id)"
  priority: WARNING
  tags: [mitre_execution, t1059]`
  );
  const [validationLoading, setValidationLoading] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<any>(null);

  // Copied indicator
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fetchStatus = () => {
    setStatusLoading(true);
    fetch('/api/falco/status')
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setStatus(data);
        }
      })
      .catch(() => {})
      .finally(() => setStatusLoading(false));
  };

  const fetchRules = (priority?: string) => {
    setRulesLoading(true);
    const url = priority && priority !== 'ALL'
      ? `/api/falco/rules?priority=${encodeURIComponent(priority)}`
      : '/api/falco/rules';

    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setRules(data.rules || []);
        }
      })
      .catch(() => {})
      .finally(() => setRulesLoading(false));
  };

  useEffect(() => {
    fetchStatus();
    fetchRules();
  }, []);

  const handlePriorityChange = (priority: string) => {
    setPriorityFilter(priority);
    fetchRules(priority);
  };

  const handleRunSimulation = async () => {
    setSimLoading(true);
    try {
      const res = await fetch('/api/falco/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: selectedScenario })
      });
      const data = await res.json();
      if (data.success) {
        setSimResult(data);
      }
    } catch {
      // Ignore
    } finally {
      setSimLoading(false);
    }
  };

  const handleValidateRule = async () => {
    setValidationLoading(true);
    setValidationResult(null);
    try {
      // Parse YAML or JSON for basic properties
      const body: any = { raw: ruleYaml };
      const lines = ruleYaml.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('- rule:') || trimmed.startsWith('rule:')) {
          body.rule = trimmed.replace(/^-\s*rule:\s*|^rule:\s*/, '').trim();
        } else if (trimmed.startsWith('condition:')) {
          body.condition = trimmed.replace(/^condition:\s*/, '').trim();
        } else if (trimmed.startsWith('output:')) {
          body.output = trimmed.replace(/^output:\s*/, '').trim();
        } else if (trimmed.startsWith('priority:')) {
          body.priority = trimmed.replace(/^priority:\s*/, '').trim();
        }
      }

      const res = await fetch('/api/falco/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      setValidationResult(data);
    } catch (err: any) {
      setValidationResult({ success: false, valid: false, errors: [err.message] });
    } finally {
      setValidationLoading(false);
    }
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredRules = rules.filter((r) => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      (r.rule || '').toLowerCase().includes(query) ||
      (r.desc || '').toLowerCase().includes(query) ||
      (r.condition || '').toLowerCase().includes(query) ||
      (r.tags || []).some((t: string) => t.toLowerCase().includes(query))
    );
  });

  return (
    <div className="space-y-6 font-mono pb-16">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Falco eBPF Runtime Threat Sensor & SOAR
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                modern_ebpf · Kernel Level
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Low-overhead kernel syscall interception, behavioral container drift analysis, and autonomous SOAR eradication.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchStatus}
            title="Refresh sensor status"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 transition-colors"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${statusLoading ? 'animate-spin' : ''}`} />
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </div>

      {/* Sensor Telemetry Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>eBPF Driver Mode</span>
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-base font-bold text-white flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>{status?.driver?.driver || 'modern_ebpf'}</span>
          </div>
          <p className="text-[11px] text-slate-500">
            Kernel ring-buffer syscall streaming
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>Kernel Compatibility</span>
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-base font-bold text-emerald-300">
            Linux 5.8+ BTF Ready
          </div>
          <p className="text-[11px] text-slate-500">
            CO-RE (Compile Once — Run Everywhere)
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>Active Detection Rules</span>
            <FileCode className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-base font-bold text-white">
            {rules.length || 18} Rules Deployed
          </div>
          <p className="text-[11px] text-slate-500">
            Mapped to MITRE ATT&CK for Containers
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5">
          <div className="text-xs text-slate-400 flex items-center justify-between">
            <span>SOAR Containment Hook</span>
            <Zap className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-base font-bold text-purple-300">
            Active · Automated
          </div>
          <p className="text-[11px] text-slate-500">
            Autonomous pod isolation & kill signals
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800/80 pb-1">
        <button
          onClick={() => setActiveTab('rules')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-bold transition-all border-b-2 ${
            activeTab === 'rules'
              ? 'bg-slate-900 text-emerald-300 border-emerald-400'
              : 'text-slate-400 hover:text-white border-transparent'
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Rules Catalog ({rules.length})</span>
        </button>
        <button
          onClick={() => setActiveTab('simulator')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-bold transition-all border-b-2 ${
            activeTab === 'simulator'
              ? 'bg-slate-900 text-cyan-300 border-cyan-400'
              : 'text-slate-400 hover:text-white border-transparent'
          }`}
        >
          <Play className="w-3.5 h-3.5" />
          <span>Syscall Simulator & SOAR</span>
        </button>
        <button
          onClick={() => setActiveTab('validator')}
          className={`flex items-center gap-2 px-4 py-2 rounded-t-lg text-xs font-bold transition-all border-b-2 ${
            activeTab === 'validator'
              ? 'bg-slate-900 text-purple-300 border-purple-400'
              : 'text-slate-400 hover:text-white border-transparent'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Custom Rule Validator</span>
        </button>
      </div>

      {/* TAB 1: RULES CATALOG */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Priority:</span>
              {['ALL', 'CRITICAL', 'WARNING', 'NOTICE'].map((p) => (
                <button
                  key={p}
                  onClick={() => handlePriorityChange(p)}
                  className={`px-2.5 py-1 rounded text-[11px] font-bold transition-colors ${
                    priorityFilter === p
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search rules or MITRE tags..."
                className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-400 outline-none w-full sm:w-64"
              />
            </div>
          </div>

          {/* Rules List */}
          <div className="space-y-2.5">
            {rulesLoading ? (
              <div className="p-8 text-center text-xs text-slate-500">Loading Falco detection rules...</div>
            ) : filteredRules.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">No detection rules found matching query.</div>
            ) : (
              filteredRules.map((rule, idx) => {
                const isExpanded = expandedRule === rule.rule;
                return (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2.5 hover:border-slate-700 transition-colors"
                  >
                    <div
                      className="flex items-center justify-between cursor-pointer"
                      onClick={() => setExpandedRule(isExpanded ? null : rule.rule)}
                    >
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          rule.priority === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                          rule.priority === 'WARNING' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-cyan-950 text-cyan-300 border border-cyan-800'
                        }`}>
                          {rule.priority}
                        </span>
                        <span className="font-bold text-white text-xs hover:text-emerald-300 transition-colors">
                          {rule.rule}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {rule.tags && rule.tags.slice(0, 2).map((t: string, i: number) => (
                          <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 hidden sm:inline-block">
                            {t}
                          </span>
                        ))}
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                      </div>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">
                      {rule.desc}
                    </p>

                    {isExpanded && (
                      <div className="pt-2 border-t border-slate-900 space-y-2 text-xs">
                        <div className="space-y-1">
                          <span className="text-[11px] text-slate-500 font-bold">Rule Condition:</span>
                          <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto">
                            {rule.condition}
                          </pre>
                        </div>
                        {rule.output && (
                          <div className="space-y-1">
                            <span className="text-[11px] text-slate-500 font-bold">Alert Output Template:</span>
                            <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-300 overflow-x-auto">
                              {rule.output}
                            </pre>
                          </div>
                        )}
                        {rule.tags && (
                          <div className="flex flex-wrap gap-1.5 pt-1">
                            <span className="text-[11px] text-slate-500 py-0.5">MITRE Tags:</span>
                            {rule.tags.map((t: string, i: number) => (
                              <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-emerald-400 border border-emerald-900/60 font-mono">
                                #{t}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* TAB 2: SYSCALL SIMULATOR & SOAR EVALUATOR */}
      {activeTab === 'simulator' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-4">
            <div className="space-y-1 border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Play className="w-4 h-4 text-cyan-400" />
                <span>Simulate eBPF Kernel Threat Scenarios</span>
              </h3>
              <p className="text-xs text-slate-400">
                Trigger synthetic kernel syscall anomalies to evaluate Falco behavioral detection and automated SOAR containment decision pipelines.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {[
                { id: 'shell-spawn', name: 'Interactive Shell Spawn', desc: 'execve(/bin/sh) spawned inside web container' },
                { id: 'sensitive-mount', name: 'Sensitive Host Mount Read', desc: 'Access to /etc/shadow or /var/run/docker.sock' },
                { id: 'shadow-read', name: 'Shadow Password Hash Access', desc: 'Read event on host credential database' },
                { id: 'crypto-miner', name: 'Outbound Stratum Miner Traffic', desc: 'Connection to mining pool TCP port 3333' },
                { id: 'nsjail-escape-attempt', name: 'nsjail Sandbox Escape Attempt', desc: 'Disallowed ptrace or mount syscall invocation' }
              ].map((sc) => (
                <button
                  key={sc.id}
                  onClick={() => setSelectedScenario(sc.id)}
                  className={`p-3.5 rounded-xl border text-left transition-all space-y-1 ${
                    selectedScenario === sc.id
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/60 shadow-lg shadow-cyan-500/10'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold text-xs text-white flex items-center justify-between">
                    <span>{sc.name}</span>
                    {selectedScenario === sc.id && <span className="text-[10px] text-cyan-400">ACTIVE</span>}
                  </div>
                  <p className="text-[11px] text-slate-400 leading-snug">{sc.desc}</p>
                </button>
              ))}
            </div>

            <div className="pt-2">
              <button
                onClick={handleRunSimulation}
                disabled={simLoading}
                className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white font-bold text-xs flex items-center gap-2 transition-colors"
              >
                <Zap className="w-4 h-4" />
                <span>{simLoading ? 'Synthesizing Syscall Sequence...' : 'Execute Threat Simulation'}</span>
              </button>
            </div>

            {/* Simulation Results (Syscall Telemetry + SOAR Decision) */}
            {simResult && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-slate-800">
                {/* eBPF Syscall Event */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-xs font-bold text-cyan-400 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5" />
                      <span>Emitted eBPF Syscall Event</span>
                    </span>
                    <span className="text-[10px] text-slate-500">{simResult.event?.time || 'Just now'}</span>
                  </div>
                  <pre className="p-3 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-200 overflow-x-auto leading-relaxed">
                    {JSON.stringify(simResult.event, null, 2)}
                  </pre>
                </div>

                {/* Automated SOAR Containment Action */}
                <div className="p-4 rounded-xl bg-slate-950 border border-purple-800/60 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-purple-400" />
                      <span>Automated SOAR Decision</span>
                    </span>
                    <span className="px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300 text-[10px] font-bold">
                      {simResult.soarAction?.action || 'CONTAIN_POD'}
                    </span>
                  </div>

                  <div className="space-y-1.5 text-xs">
                    <div><strong className="text-slate-400">Playbook:</strong> <span className="text-white">{simResult.soarAction?.playbook || 'Autonomous Container Isolation'}</span></div>
                    <div><strong className="text-slate-400">Target Resource:</strong> <code className="text-cyan-400">{simResult.soarAction?.target || 'pod/web-operative'}</code></div>
                    <div><strong className="text-slate-400">Containment Verdict:</strong> <span className="text-emerald-400">{simResult.soarAction?.verdict || 'CONTAINED'}</span></div>
                  </div>

                  {simResult.soarAction?.remediationCommand && (
                    <div className="space-y-1 pt-1">
                      <div className="flex items-center justify-between text-[11px] text-slate-400">
                        <span>Remediation CLI Command:</span>
                        <button
                          onClick={() => handleCopy(simResult.soarAction.remediationCommand, 'soar-cmd')}
                          className="text-purple-400 hover:text-purple-300 flex items-center gap-1"
                        >
                          {copiedKey === 'soar-cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>Copy</span>
                        </button>
                      </div>
                      <code className="block p-2 rounded bg-slate-900 border border-slate-800 text-[11px] text-purple-300 overflow-x-auto">
                        {simResult.soarAction.remediationCommand}
                      </code>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: CUSTOM RULE VALIDATOR */}
      {activeTab === 'validator' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-4">
            <div className="space-y-1 border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <FileCode className="w-4 h-4 text-purple-400" />
                <span>Custom Falco Rule Validator (validateFalcoRule)</span>
              </h3>
              <p className="text-xs text-slate-400">
                Write or customize Falco rule definitions and validate syntax, condition filters, and output tokens before pushing to cluster.
              </p>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Falco Rule YAML / JSON:</span>
                <button
                  onClick={() => setRuleYaml(
`- rule: Terminal Spawn in Isolated Sandbox
  desc: Detects shell execution inside ctf-sandboxes namespace
  condition: k8s.ns.name = "ctf-sandboxes" and proc.name in (bash, sh, zsh)
  output: "Shell initiated in CTF sandbox (user=%user.name pod=%k8s.pod.name)"
  priority: NOTICE
  tags: [ctf_telemetry, mitre_execution]`
                  )}
                  className="text-purple-400 hover:text-purple-300 underline"
                >
                  Load CTF Sandbox Preset
                </button>
              </div>
              <textarea
                value={ruleYaml}
                onChange={(e) => setRuleYaml(e.target.value)}
                rows={8}
                className="w-full rounded-lg bg-slate-950 border border-slate-700 p-3 text-xs text-slate-200 font-mono focus:border-purple-500 outline-none leading-relaxed"
              />
            </div>

            <button
              onClick={handleValidateRule}
              disabled={validationLoading || !ruleYaml.trim()}
              className="px-5 py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 text-white font-bold text-xs flex items-center gap-2 transition-colors"
            >
              <CheckCircle2 className="w-4 h-4" />
              <span>{validationLoading ? 'Validating Syntax...' : 'Validate Rule Syntax'}</span>
            </button>

            {validationResult && (
              <div className={`p-4 rounded-xl border space-y-2 text-xs font-mono ${
                validationResult.valid
                  ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/20 border-rose-500/40 text-rose-300'
              }`}>
                <div className="flex items-center gap-2 font-bold text-sm">
                  {validationResult.valid ? (
                    <>
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Rule Validation Passed! Clean AST and syntax.</span>
                    </>
                  ) : (
                    <>
                      <AlertTriangle className="w-4 h-4 text-rose-400" />
                      <span>Validation Errors Encountered:</span>
                    </>
                  )}
                </div>

                {validationResult.errors && validationResult.errors.length > 0 && (
                  <ul className="list-disc pl-5 space-y-1 text-xs">
                    {validationResult.errors.map((err: string, i: number) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
