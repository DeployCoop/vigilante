'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Flag,
  Shield,
  Terminal,
  Play,
  Cpu,
  Radar,
  Radio,
  Clock,
  Sparkles,
  Key,
  FolderPlus,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  ArrowRight,
  ExternalLink,
  HelpCircle,
  Wrench,
  BookOpen,
  FileSearch,
  GitFork,
  Flame,
  Award,
  RefreshCw
} from 'lucide-react';

export default function CTFEventGuidePage() {
  const [activeTab, setActiveTab] = useState<'onboarding' | 'playbook' | 'workbench' | 'scoring' | 'cheatsheet'>('onboarding');
  
  // Readiness status
  const [status, setStatus] = useState<any>(null);
  const [sandboxes, setSandboxes] = useState<any[]>([]);
  const [loadingStatus, setLoadingStatus] = useState(true);

  // Workspace Scaffolder state
  const [targetDir, setTargetDir] = useState('./ctf-workspace');
  const [teamName, setTeamName] = useState('CyberTeam-1');
  const [tournamentUrl, setTournamentUrl] = useState('https://ctf.vigilante.local');
  const [scaffoldLoading, setScaffoldLoading] = useState(false);
  const [scaffoldResult, setScaffoldResult] = useState<any>(null);
  const [scaffoldError, setScaffoldError] = useState<string | null>(null);

  // Solver Workbench state
  const [solverTool, setSolverTool] = useState<'cyclic' | 'cipher' | 'jwt' | 'rsa' | 'xor'>('cyclic');
  const [cyclicLength, setCyclicLength] = useState('256');
  const [cyclicPattern, setCyclicPattern] = useState('');
  const [cyclicNeedle, setCyclicNeedle] = useState('');
  const [cyclicOffset, setCyclicOffset] = useState<number | null>(null);
  const [cipherInput, setCipherInput] = useState('');
  const [cipherCandidates, setCipherCandidates] = useState<any[]>([]);
  const [jwtToken, setJwtToken] = useState('');
  const [jwtAnalysis, setJwtAnalysis] = useState<any>(null);
  const [rsaModulus, setRsaModulus] = useState('');
  const [rsaResult, setRsaResult] = useState<any>(null);
  const [xorCt1, setXorCt1] = useState('');
  const [xorCt2, setXorCt2] = useState('');
  const [xorCrib, setXorCrib] = useState('VIGILANTE{');
  const [xorResult, setXorResult] = useState<any>(null);
  const [solverLoading, setSolverLoading] = useState(false);
  const [solverError, setSolverError] = useState<string | null>(null);

  // Copied indicator
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const fetchStatus = () => {
    setLoadingStatus(true);
    Promise.all([
      fetch('/api/status').then(r => r.json()).catch(() => ({})),
      fetch('/api/ctf/sandboxes').then(r => r.json()).catch(() => ({}))
    ]).then(([st, sb]) => {
      setStatus(st);
      setSandboxes(sb.sandboxes || []);
      setLoadingStatus(false);
    });
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleScaffoldWorkspace = async () => {
    setScaffoldLoading(true);
    setScaffoldError(null);
    try {
      const res = await fetch('/api/ctf/workspace', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'init',
          targetDir,
          teamName,
          tournamentUrl
        })
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to initialize workspace');
      }
      setScaffoldResult(data);
    } catch (err: any) {
      setScaffoldError(err.message);
    } finally {
      setScaffoldLoading(false);
    }
  };

  const handleRunSolver = async () => {
    setSolverLoading(true);
    setSolverError(null);
    try {
      let body: any = {};
      if (solverTool === 'cyclic') {
        if (cyclicNeedle.trim()) {
          body = { tool: 'cyclic_offset', pattern: cyclicPattern || undefined, needle: cyclicNeedle.trim() };
        } else {
          body = { tool: 'cyclic_generate', length: parseInt(cyclicLength, 10) || 256 };
        }
      } else if (solverTool === 'cipher') {
        body = { tool: 'cipher_identify', input: cipherInput };
      } else if (solverTool === 'jwt') {
        body = { tool: 'jwt_inspect', token: jwtToken };
      } else if (solverTool === 'rsa') {
        body = { tool: 'rsa_factor', n: rsaModulus.trim() };
      } else if (solverTool === 'xor') {
        body = { tool: 'xor_crib', ct1: xorCt1.trim(), ct2: xorCt2.trim(), crib: xorCrib.trim() };
      }

      const res = await fetch('/api/ctf/tools', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Solver failed');
      }

      if (solverTool === 'cyclic') {
        if (data.pattern) setCyclicPattern(data.pattern);
        if (data.offset !== undefined) setCyclicOffset(data.offset);
      } else if (solverTool === 'cipher') {
        setCipherCandidates(data.candidates || []);
      } else if (solverTool === 'jwt') {
        setJwtAnalysis(data);
      } else if (solverTool === 'rsa') {
        setRsaResult(data);
      } else if (solverTool === 'xor') {
        setXorResult(data);
      }
    } catch (err: any) {
      setSolverError(err.message);
    } finally {
      setSolverLoading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-8 font-mono pb-16">
      {/* Top Header Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-cyan-500/40 bg-gradient-to-r from-cyan-950/40 via-slate-900/90 to-slate-950 p-6 shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-[11px] font-bold tracking-wider uppercase">
                CTF Cyber Range Platform
              </span>
              <span className="px-2.5 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 text-[11px]">
                Tournament Edition
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
              <Flag className="w-7 h-7 text-cyan-400" />
              <span>Player Field Manual & Operational Guide</span>
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 max-w-3xl leading-relaxed">
              Welcome to the Vigilante Cyber Range. Use this manual to initialize your participant workspace, master
              Vigilante's multi-vector investigation tools, and harness the built-in Solver Workbench and Socratic AI Mentor.
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <Link
              href="/ctf"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-all shadow-lg shadow-cyan-500/20"
            >
              <Play className="w-4 h-4 fill-current" />
              <span>Launch CTF Arena</span>
            </Link>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex flex-wrap gap-2 pt-6 border-t border-slate-800/80 mt-6">
          <button
            onClick={() => setActiveTab('onboarding')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              activeTab === 'onboarding'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <FolderPlus className="w-3.5 h-3.5" />
            <span>1. Readiness & Workspace</span>
          </button>
          <button
            onClick={() => setActiveTab('playbook')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              activeTab === 'playbook'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>2. The 5-Step Playbook</span>
          </button>
          <button
            onClick={() => setActiveTab('workbench')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              activeTab === 'workbench'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <Wrench className="w-3.5 h-3.5" />
            <span>3. Solver Workbench</span>
          </button>
          <button
            onClick={() => setActiveTab('scoring')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              activeTab === 'scoring'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <Award className="w-3.5 h-3.5" />
            <span>4. Tournament Scoring</span>
          </button>
          <button
            onClick={() => setActiveTab('cheatsheet')}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              activeTab === 'cheatsheet'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200 border border-transparent'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>5. Command Cheat Sheet</span>
          </button>
        </div>
      </div>

      {/* Tab 1: Readiness & Workspace */}
      {activeTab === 'onboarding' && (
        <div className="space-y-6">
          {/* Pre-flight status cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-cyan-400" />
                  Cluster Runtime
                </span>
                <button onClick={fetchStatus} title="Refresh status" className="text-slate-500 hover:text-cyan-400">
                  <RefreshCw className={`w-3 h-3 ${loadingStatus ? 'animate-spin' : ''}`} />
                </button>
              </div>
              <div className="text-sm font-bold text-white flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${status?.cluster?.connected ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
                <span>{status?.cluster?.provider ? `${status.cluster.provider.toUpperCase()} (${status.cluster.name || 'default'})` : 'Local Cluster'}</span>
              </div>
              <p className="text-[11px] text-slate-500">
                {status?.cluster?.connected ? 'Connected to Kubernetes API' : 'Not running. Start via `vigilante up`'}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <div className="text-xs text-slate-400 flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-cyan-400" />
                <span>Local TLS & Domain</span>
              </div>
              <div className="text-sm font-bold text-white flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${status?.certs?.valid ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                <span>*.vigilante.local</span>
              </div>
              <p className="text-[11px] text-slate-500">
                {status?.certs?.valid ? 'mkcert CA trusted & /etc/hosts mapped' : 'Synchronize with `vigilante hostr`'}
              </p>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
              <div className="text-xs text-slate-400 flex items-center gap-1.5">
                <Flag className="w-3.5 h-3.5 text-cyan-400" />
                <span>Active Ephemeral Sandboxes</span>
              </div>
              <div className="text-sm font-bold text-cyan-300">
                {sandboxes.length} Pods Allocated
              </div>
              <p className="text-[11px] text-slate-500">
                Managed under 30-min team TTLs with nsjail containment
              </p>
            </div>
          </div>

          {/* 1-Click Workspace Scaffold Card */}
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <FolderPlus className="w-4 h-4 text-cyan-400" />
                  <span>Scaffold Local Participant Workspace</span>
                </h3>
                <p className="text-xs text-slate-400 pt-1">
                  Generates categorized challenge directories (<code>web/</code>, <code>pwn/</code>, <code>crypto/</code>, <code>rev/</code>, <code>forensics/</code>, <code>writeups/</code>)
                  with per-challenge briefings, README files, and starter Python exploit templates (<code>pwntools</code>, <code>requests</code>).
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">Target Workspace Directory</span>
                <input
                  value={targetDir}
                  onChange={(e) => setTargetDir(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </label>
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">Team / Handle Name</span>
                <input
                  value={teamName}
                  onChange={(e) => setTeamName(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </label>
              <label className="space-y-1">
                <span className="text-[11px] text-slate-400">Tournament Endpoint</span>
                <input
                  value={tournamentUrl}
                  onChange={(e) => setTournamentUrl(e.target.value)}
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </label>
            </div>

            <div className="flex justify-end pt-1">
              <button
                onClick={handleScaffoldWorkspace}
                disabled={scaffoldLoading}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg flex items-center space-x-1.5 transition-colors disabled:opacity-50"
              >
                <FolderPlus className="w-3.5 h-3.5" />
                <span>{scaffoldLoading ? 'Scaffolding Workspace…' : 'Initialize Workspace'}</span>
              </button>
            </div>

            {scaffoldError && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-300 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
                <span>{scaffoldError}</span>
              </div>
            )}

            {scaffoldResult && (
              <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 space-y-2">
                <div className="flex items-center gap-2 font-bold">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Workspace initialized successfully!</span>
                </div>
                <p className="text-slate-300">
                  Scaffolded <span className="font-bold text-white">{scaffoldResult.scaffoldedCount} challenge folders</span> at{' '}
                  <code className="bg-slate-950 px-1.5 py-0.5 rounded text-cyan-300 border border-slate-700">{scaffoldResult.workspacePath}</code>.
                </p>
                <div className="text-[11px] text-slate-400">
                  Explore challenge templates and writeup templates:
                  <div className="mt-1 font-mono text-[10px] bg-slate-950 p-2 rounded border border-slate-800 text-slate-300 space-y-0.5">
                    <div>├── pwn/pwn-rop-bof/ (solve.py, README.md)</div>
                    <div>├── web/web-auth-bypass/ (exploit.py, README.md)</div>
                    <div>├── crypto/crypto-oracle/ (solve.py, README.md)</div>
                    <div>└── writeups/ (RFC 4880 GPG signed writeups)</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: The 5-Step Playbook */}
      {activeTab === 'playbook' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-6">
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-cyan-400" />
                <span>The 5-Step Vigilante CTF Investigation Playbook</span>
              </h3>
              <p className="text-xs text-slate-400">
                Follow this battle-tested operational sequence to triage, exploit, and document challenges during the competition.
              </p>
            </div>

            <div className="space-y-4">
              {/* Step 1 */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs uppercase">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[10px] border border-cyan-500/40">1</span>
                  <span>Spawn Ephemeral Target Sandboxes</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pl-7">
                  Navigate to the <Link href="/ctf" className="text-cyan-400 underline hover:text-cyan-300">CTF Arena (/ctf)</Link>.
                  Click <strong>Spawn Sandbox</strong> on any challenge card. Vigilante spins up an isolated Kubernetes container running under
                  <code>nsjail</code> process isolation with a 30-minute TTL, returning your dedicated IP and port.
                </p>
                <div className="pl-7 text-[11px] text-slate-500">
                  CLI shortcut: <code className="text-slate-300">vigilante ctf</code>
                </div>
              </div>

              {/* Step 2 */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs uppercase">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[10px] border border-cyan-500/40">2</span>
                  <span>Network Recon & Attack Surface Profiling</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pl-7">
                  Use the <Link href="/nastymap" className="text-cyan-400 underline hover:text-cyan-300">NastyMap Visualizer (/nastymap)</Link> or
                  built-in Nmap scanner to probe open ports, banner versions, and web endpoints. Identify non-standard headers, exposed debug APIs,
                  and software fingerprints.
                </p>
                <div className="pl-7 text-[11px] text-slate-500">
                  CLI shortcut: <code className="text-slate-300">vigilante scan</code> or <code className="text-slate-300">vigilante map</code>
                </div>
              </div>

              {/* Step 3 */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs uppercase">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[10px] border border-cyan-500/40">3</span>
                  <span>Deep Forensic Carving & Traffic Dissection</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pl-7">
                  For forensics and network challenges, launch <Link href="/forensics" className="text-cyan-400 underline hover:text-cyan-300">PCAP Forensics (/forensics)</Link> to
                  carve HTTP/SMB file drops, reconstruct TCP streams, and decrypt TLS sessions using SSLKEYLOGFILE. Use the
                  <Link href="/sniffer" className="text-cyan-400 underline hover:text-cyan-300"> Live Sniffer (/sniffer)</Link> to dissect Ethernet, IP, TCP, and UDP frames in real time.
                </p>
                <div className="pl-7 text-[11px] text-slate-500">
                  CLI shortcut: <code className="text-slate-300">vigilante forensics</code> or <code className="text-slate-300">vigilante sniffer</code>
                </div>
              </div>

              {/* Step 4 */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs uppercase">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[10px] border border-cyan-500/40">4</span>
                  <span>Socratic AI Mentor & Crash Triage</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pl-7">
                  Stuck on a challenge? Open the <strong>Socratic Mentor</strong> on the CTF Arena. Select your guidance tier:
                  <span className="text-slate-200 font-semibold"> Tier 1 (Conceptual)</span>, <span className="text-slate-200 font-semibold"> Tier 2 (Structural Guidance)</span>, or
                  <span className="text-slate-200 font-semibold"> Tier 3 (Technical Mechanics)</span>. The mentor guides your thinking without revealing the flag.
                  For binary crashes, paste your GDB or segfault registers into the Crash Analyzer for instant root-cause diagnosis.
                </p>
                <div className="pl-7 text-[11px] text-slate-500">
                  CLI shortcut: <code className="text-slate-300">vigilante ai</code>
                </div>
              </div>

              {/* Step 5 */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
                <div className="flex items-center gap-2 text-cyan-400 font-bold text-xs uppercase">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center text-[10px] border border-cyan-500/40">5</span>
                  <span>Flag Submission, Replay Recording & Merkle Seals</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed pl-7">
                  Submit your captured flag in the format <code className="text-cyan-300">VIGILANTE&#123;...&#125;</code> on the CTF Arena.
                  After solving, generate an RFC 4880 GPG-signed writeup or seal your solve evidence into the cryptographic Merkle ledger
                  for prize qualification and verifiable chain-of-custody.
                </p>
                <div className="pl-7 text-[11px] text-slate-500">
                  CLI shortcut: <code className="text-slate-300">vigilante ctf submit &lt;chal-id&gt; &lt;flag&gt;</code>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Interactive Solver Workbench */}
      {activeTab === 'workbench' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                  <Wrench className="w-4 h-4 text-cyan-400" />
                  <span>CTF Solver Workbench (ctf-tools)</span>
                </h3>
                <p className="text-xs text-slate-400 pt-1">
                  Execute deterministic exploit math, pattern generation, token forensics, and cipher analysis powered by Vigilante's solver engine.
                </p>
              </div>

              <div className="flex flex-wrap gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                <button
                  onClick={() => setSolverTool('cyclic')}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${solverTool === 'cyclic' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  Cyclic Buffer
                </button>
                <button
                  onClick={() => setSolverTool('cipher')}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${solverTool === 'cipher' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  Cipher Auto-ID
                </button>
                <button
                  onClick={() => setSolverTool('jwt')}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${solverTool === 'jwt' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  JWT Inspector
                </button>
                <button
                  onClick={() => setSolverTool('rsa')}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${solverTool === 'rsa' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  RSA Factorizer
                </button>
                <button
                  onClick={() => setSolverTool('xor')}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${solverTool === 'xor' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
                >
                  XOR Crib Drag
                </button>
              </div>
            </div>

            {/* Tool 1: Cyclic Buffer */}
            {solverTool === 'cyclic' && (
              <div className="space-y-4 pt-2">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-3 p-4 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-xs font-bold text-cyan-300">Generate De Bruijn Pattern</span>
                    <label className="space-y-1 block">
                      <span className="text-[11px] text-slate-400">Buffer Length (Bytes)</span>
                      <input
                        value={cyclicLength}
                        onChange={(e) => setCyclicLength(e.target.value)}
                        placeholder="256"
                        className="w-full rounded bg-slate-900 border border-slate-700 px-3 py-1.5 text-xs text-white"
                      />
                    </label>
                    <button
                      onClick={handleRunSolver}
                      disabled={solverLoading}
                      className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs rounded font-semibold"
                    >
                      Generate Pattern
                    </button>
                    {cyclicPattern && (
                      <div className="space-y-1 pt-2">
                        <div className="flex items-center justify-between text-[11px] text-slate-400">
                          <span>Output Pattern ({cyclicPattern.length} chars):</span>
                          <button
                            onClick={() => handleCopy(cyclicPattern, 'cyclic-pat')}
                            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                          >
                            {copiedKey === 'cyclic-pat' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                            <span>Copy</span>
                          </button>
                        </div>
                        <textarea
                          readOnly
                          rows={3}
                          value={cyclicPattern}
                          className="w-full rounded bg-slate-900 border border-slate-800 p-2 text-[11px] text-slate-300 font-mono"
                        />
                      </div>
                    )}
                  </div>

                  <div className="space-y-3 p-4 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-xs font-bold text-cyan-300">Find Crash Offset (EIP / RIP)</span>
                    <label className="space-y-1 block">
                      <span className="text-[11px] text-slate-400">Crash Value (Hex e.g. 0x61413961 or String)</span>
                      <input
                        value={cyclicNeedle}
                        onChange={(e) => setCyclicNeedle(e.target.value)}
                        placeholder="0x61413961"
                        className="w-full rounded bg-slate-900 border border-slate-700 px-3 py-1.5 text-xs text-white"
                      />
                    </label>
                    <button
                      onClick={handleRunSolver}
                      disabled={solverLoading}
                      className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs rounded font-semibold"
                    >
                      Calculate Offset
                    </button>
                    {cyclicOffset !== null && (
                      <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded text-xs text-emerald-300 mt-2">
                        Exact Buffer Offset: <span className="text-white font-bold text-sm">{cyclicOffset}</span> bytes
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Tool 2: Cipher Auto-ID */}
            {solverTool === 'cipher' && (
              <div className="space-y-4 pt-2">
                <label className="space-y-1 block">
                  <span className="text-[11px] text-slate-400">Ciphertext / Encoded String</span>
                  <textarea
                    rows={3}
                    value={cipherInput}
                    onChange={(e) => setCipherInput(e.target.value)}
                    placeholder="Paste Base64, Hex, ROT13, or URL-encoded payload..."
                    className="w-full rounded bg-slate-950 border border-slate-700 p-3 text-xs text-white placeholder:text-slate-600 font-mono"
                  />
                </label>
                <button
                  onClick={handleRunSolver}
                  disabled={solverLoading || !cipherInput.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs rounded font-semibold disabled:opacity-50"
                >
                  Analyze & Decode
                </button>

                {cipherCandidates.length > 0 && (
                  <div className="space-y-2 pt-2">
                    <span className="text-xs font-bold text-slate-300">Identified Encodings & Decoded Text:</span>
                    <div className="space-y-2">
                      {cipherCandidates.map((c, i) => (
                        <div key={i} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-bold text-cyan-300">{c.type}</span>
                            <span className="text-[10px] text-slate-500">Confidence: {c.confidence}</span>
                          </div>
                          <div className="bg-slate-900 p-2 rounded text-xs text-emerald-300 font-mono break-all">
                            {c.decoded || JSON.stringify(c.header || c)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Tool 3: JWT Inspector */}
            {solverTool === 'jwt' && (
              <div className="space-y-4 pt-2">
                <label className="space-y-1 block">
                  <span className="text-[11px] text-slate-400">JSON Web Token (Bearer)</span>
                  <textarea
                    rows={3}
                    value={jwtToken}
                    onChange={(e) => setJwtToken(e.target.value)}
                    placeholder="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..."
                    className="w-full rounded bg-slate-950 border border-slate-700 p-3 text-xs text-white font-mono"
                  />
                </label>
                <button
                  onClick={handleRunSolver}
                  disabled={solverLoading || !jwtToken.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs rounded font-semibold disabled:opacity-50"
                >
                  Inspect JWT Header & Claims
                </button>

                {jwtAnalysis && (
                  <div className="space-y-3 pt-2">
                    {jwtAnalysis.vulnerabilities?.length > 0 && (
                      <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-300 space-y-1">
                        <span className="font-bold text-red-400">Vulnerabilities Detected:</span>
                        {jwtAnalysis.vulnerabilities.map((v: string, i: number) => (
                          <div key={i}>• {v}</div>
                        ))}
                      </div>
                    )}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                        <span className="text-slate-500 font-bold">Header</span>
                        <pre className="text-cyan-300 text-[11px] overflow-x-auto">{JSON.stringify(jwtAnalysis.header, null, 2)}</pre>
                      </div>
                      <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                        <span className="text-slate-500 font-bold">Payload Claims</span>
                        <pre className="text-emerald-300 text-[11px] overflow-x-auto">{JSON.stringify(jwtAnalysis.payload, null, 2)}</pre>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Tool 4: RSA Factorizer */}
            {solverTool === 'rsa' && (
              <div className="space-y-4 pt-2">
                <label className="space-y-1 block">
                  <span className="text-[11px] text-slate-400">RSA Modulus N (Decimal)</span>
                  <input
                    value={rsaModulus}
                    onChange={(e) => setRsaModulus(e.target.value)}
                    placeholder="Enter large composite modulus N..."
                    className="w-full rounded bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-white font-mono"
                  />
                </label>
                <button
                  onClick={handleRunSolver}
                  disabled={solverLoading || !rsaModulus.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs rounded font-semibold disabled:opacity-50"
                >
                  Factorize (Trial / Fermat / Wiener)
                </button>

                {rsaResult && (
                  <div className={`p-4 rounded-lg border text-xs space-y-2 ${
                    rsaResult.factorized ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                  }`}>
                    <div className="font-bold">
                      {rsaResult.factorized ? `Factorization Succeeded via ${rsaResult.method}!` : 'Factorization Resisted'}
                    </div>
                    {rsaResult.factorized && (
                      <div className="space-y-1 text-[11px] text-slate-300 font-mono">
                        <div>p = <span className="text-cyan-300">{rsaResult.p}</span></div>
                        <div>q = <span className="text-cyan-300">{rsaResult.q}</span></div>
                        {rsaResult.d && <div>d = <span className="text-white font-bold">{rsaResult.d}</span></div>}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Tool 5: XOR Crib Drag */}
            {solverTool === 'xor' && (
              <div className="space-y-4 pt-2">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <label className="space-y-1 block">
                    <span className="text-[11px] text-slate-400">Ciphertext 1 (Hex)</span>
                    <input
                      value={xorCt1}
                      onChange={(e) => setXorCt1(e.target.value)}
                      placeholder="Hex bytes e.g. 1a2b3c..."
                      className="w-full rounded bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-white font-mono"
                    />
                  </label>
                  <label className="space-y-1 block">
                    <span className="text-[11px] text-slate-400">Ciphertext 2 (Hex)</span>
                    <input
                      value={xorCt2}
                      onChange={(e) => setXorCt2(e.target.value)}
                      placeholder="Hex bytes e.g. 4d5e6f..."
                      className="w-full rounded bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-white font-mono"
                    />
                  </label>
                </div>
                <label className="space-y-1 block">
                  <span className="text-[11px] text-slate-400">Known Plaintext Crib</span>
                  <input
                    value={xorCrib}
                    onChange={(e) => setXorCrib(e.target.value)}
                    placeholder="VIGILANTE{"
                    className="w-full rounded bg-slate-950 border border-slate-700 px-3 py-2 text-xs text-white font-mono"
                  />
                </label>
                <button
                  onClick={handleRunSolver}
                  disabled={solverLoading || !xorCt1.trim() || !xorCt2.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs rounded font-semibold disabled:opacity-50"
                >
                  Drag Crib
                </button>

                {xorResult && (
                  <div className="space-y-2 pt-2">
                    <span className="text-xs text-slate-400">Discovered Plaintext Matches:</span>
                    {xorResult.matches?.length === 0 ? (
                      <p className="text-xs text-slate-500">No printable ASCII matches found for this crib.</p>
                    ) : (
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {xorResult.matches.map((m: any, i: number) => (
                          <div key={i} className="p-2 bg-slate-950 rounded border border-slate-800 text-xs flex justify-between">
                            <span className="text-slate-500">Offset {m.offset}:</span>
                            <span className="text-cyan-300 font-bold font-mono">{m.revealedPlaintext}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {solverError && (
              <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-xs text-red-300">
                {solverError}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 4: Tournament Scoring & Rules */}
      {activeTab === 'scoring' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-6">
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Award className="w-4 h-4 text-cyan-400" />
                <span>Tournament Scoring Rules & Anti-Cheat Architecture</span>
              </h3>
              <p className="text-xs text-slate-400">
                Understanding point decay, first-blood multipliers, and tick phases across competition modes.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">Jeopardy Mode Scoring</span>
                <ul className="text-xs text-slate-300 space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 font-bold">•</span>
                    <span><strong>Dynamic Decay Points:</strong> Challenges start at <strong>500 pts</strong> and dynamically decay down to <strong>100 pts</strong> as more teams solve them (parabolic decay over 30 solves).</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 font-bold">•</span>
                    <span><strong>First Blood Bonus:</strong> 1st Blood: <strong>+10%</strong> 🩸, 2nd Blood: <strong>+5%</strong> 🥈, 3rd Blood: <strong>+2%</strong> 🥉.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-cyan-400 font-bold">•</span>
                    <span><strong>HMAC Dynamic Flags:</strong> Every team receives an HMAC-derived flag unique to their team ID to prevent unauthorized flag sharing.</span>
                  </li>
                </ul>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <span className="text-xs font-bold text-purple-400 uppercase tracking-wider">Attack-Defense Mode (AD)</span>
                <ul className="text-xs text-slate-300 space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">•</span>
                    <span><strong>120-Second Ticks:</strong> Each tick executes <code>FLAG_INJECT</code>, <code>SLA_CHECK</code>, and <code>POINT_CALCULATION</code>.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">•</span>
                    <span><strong>Defense Points:</strong> Retain +100 defense points per tick if your service passes health and integrity probes.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">•</span>
                    <span><strong>Attack Points:</strong> Steal flags from opponent services for +150 attack points per capture.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">•</span>
                    <span><strong>SLA Penalties:</strong> Service FAULTY (-25 pts) or DOWN (-50 pts).</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 5: Command Cheat Sheet */}
      {activeTab === 'cheatsheet' && (
        <div className="space-y-6">
          <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-xl space-y-4">
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Web Ops Portal ⟷ Ink Terminal CLI Parity Cheat Sheet</span>
              </h3>
              <p className="text-xs text-slate-400">
                Every operation available in this web portal can also be executed directly from your terminal.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="text-slate-500 border-b border-slate-800">
                    <th className="py-2.5 pr-4">Operational Action</th>
                    <th className="py-2.5 pr-4">Web Portal Route</th>
                    <th className="py-2.5 pr-4">Terminal CLI Command</th>
                    <th className="py-2.5">Keybinding</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">CTF Cyber Range Arena</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/ctf">/ctf</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante ctf</code></td>
                    <td className="py-2.5 text-slate-400">[f]</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">Network Recon & Topology</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/nastymap">/nastymap</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante scan</code> / <code>map</code></td>
                    <td className="py-2.5 text-slate-400">[5]</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">AI Security Analyst (NIST)</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/analyst">/analyst</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante ai</code></td>
                    <td className="py-2.5 text-slate-400">[7]</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">PCAP Stream Forensics</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/forensics">/forensics</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante forensics</code></td>
                    <td className="py-2.5 text-slate-400">[z]</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">Live Packet Sniffer</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/sniffer">/sniffer</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante sniffer</code></td>
                    <td className="py-2.5 text-slate-400">[u]</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">Kernel eBPF Process Lineage</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/lineage">/lineage</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante lineage</code></td>
                    <td className="py-2.5 text-slate-400">[e]</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">BattleStation Live SOC</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/battlestation">/battlestation</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante battle</code></td>
                    <td className="py-2.5 text-slate-400">[l]</td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-4 font-bold text-white">Access Control (CASL RBAC)</td>
                    <td className="py-2.5 pr-4 text-cyan-400"><Link href="/settings/access">/settings/access</Link></td>
                    <td className="py-2.5 pr-4"><code>vigilante authz</code></td>
                    <td className="py-2.5 text-slate-400">[a]</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
