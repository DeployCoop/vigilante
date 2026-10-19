'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Sparkles,
  CheckCircle2,
  Circle,
  Copy,
  Check,
  Download,
  Terminal,
  Cpu,
  Server,
  Layers,
  FileCheck,
  AlertTriangle,
  ExternalLink,
  MessageSquare,
  HelpCircle,
  Clock,
  Laptop,
  ArrowRight,
  ShieldCheck,
  Search,
  Bot,
  Play
} from 'lucide-react';

interface ChecklistItem {
  id: string;
  title: string;
  command?: string;
  expected: string;
  description: string;
  category: 'prereq' | 'ai' | 'vigil' | 'data' | 'bonus';
}

const CHECKLIST_ITEMS: ChecklistItem[] = [
  {
    id: 'docker',
    title: 'Docker Engine Verification',
    command: 'docker run --rm hello-world',
    expected: 'Hello from Docker! ... This message shows that your installation appears to be working correctly.',
    description: 'Verifies that Docker daemon is running and has container execution rights.',
    category: 'prereq'
  },
  {
    id: 'ollama',
    title: 'Ollama & Local Qwen Model Test',
    command: 'ollama run qwen2.5:3b "Reply with one word: ready"',
    expected: 'ready',
    description: 'Ensure Ollama is running and has cached qwen2.5:3b (or qwen2.5:1.5b on 8 GB RAM machines).',
    category: 'ai'
  },
  {
    id: 'vigil_localhost',
    title: 'Vigil-SOC at Localhost & Model Assignment',
    expected: 'Settings → AI Config → Model Assignment mapped to Ollama qwen2.5',
    description: 'Vigil web interface loads at localhost and the local LLM worker is configured.',
    category: 'vigil'
  },
  {
    id: 'dataset_unpack',
    title: 'Dataset Archive Checksum & Unpack',
    expected: 'Archive unpacks cleanly with no corruption (size ~10 MB)',
    description: 'Download the dataset from Google Drive, verify integrity, and extract loglm-findings.parquet.',
    category: 'data'
  },
  {
    id: 'loglm_upload',
    title: 'LogLM Findings Ingestion',
    expected: '"Imported 256 findings" confirmation message in Vigil',
    description: 'Upload loglm-findings.parquet into Vigil findings ingest pipeline.',
    category: 'data'
  },
  {
    id: 'chat_tools',
    title: 'Bonus: Socratic Chat Tool Calling',
    expected: 'Vigil Agent executes tool calls against the 256 ingested findings',
    description: 'Ask Vigil Chat to inspect or summarize findings and observe autonomous tool calling.',
    category: 'bonus'
  }
];

export default function WorkshopIntroPage() {
  const [completed, setCompleted] = useState<Record<string, boolean>>({});
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Attendee report state
  const [osName, setOsName] = useState<string>('mac-arm');
  const [ramSize, setRamSize] = useState<string>('16 GB');
  const [modelChosen, setModelChosen] = useState<string>('qwen2.5:3b');
  const [duration, setDuration] = useState<string>('20 mins');
  const [statusResult, setStatusResult] = useState<'success' | 'stuck'>('success');
  const [mac32kTested, setMac32kTested] = useState<string>('tested-ok');
  const [notesFriction, setNotesFriction] = useState<string>('Setup went smoothly end-to-end.');
  const [reportCopied, setReportCopied] = useState<boolean>(false);

  // Load checklist state from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('aha-event-checklist-v1');
      if (saved) {
        setCompleted(JSON.parse(saved));
      }
    } catch {
      // Ignore storage errors
    }
  }, []);

  const toggleCheck = (id: string) => {
    setCompleted((prev) => {
      const next = { ...prev, [id]: !prev[id] };
      try {
        localStorage.setItem('aha-event-checklist-v1', JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
  };

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const completedCount = CHECKLIST_ITEMS.filter((item) => completed[item.id]).length;
  const progressPct = Math.round((completedCount / CHECKLIST_ITEMS.length) * 100);

  const generateReportText = () => {
    const isDone = completedCount >= 5;
    const checklistStatus = CHECKLIST_ITEMS.map((item) => {
      const statusIcon = completed[item.id] ? '✅' : '❌';
      return `- ${statusIcon} ${item.title}: ${completed[item.id] ? 'Passed' : 'Pending/Failed'}`;
    }).join('\n');

    return `*Agents Hunting Agents — Attendee Setup Report*
Status: ${statusResult === 'success' ? '🚀 Complete & Ready' : '⚠️ Stuck / Hit Friction'}
OS: ${osName}
RAM: ${ramSize}
Model: ${modelChosen}
Time taken: ~${duration}
Mac Silicon 32k context: ${mac32kTested}

*Checklist Progress (${completedCount}/${CHECKLIST_ITEMS.length}):*
${checklistStatus}

*Notes / Friction / Stuck details:*
${notesFriction || 'None'}`;
  };

  const copyReport = () => {
    const text = generateReportText();
    navigator.clipboard.writeText(text);
    setReportCopied(true);
    setTimeout(() => setReportCopied(false), 2500);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-16">
      {/* Event Alert & Top Header */}
      <div className="relative overflow-hidden rounded-2xl border border-cyan-500/40 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/40 p-6 sm:p-8 shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none -mr-20 -mt-20"></div>

        <div className="relative z-10 space-y-4">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-400 font-semibold">
              <Sparkles className="w-3.5 h-3.5" />
              Event Tomorrow: Hands-on Workshop
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-xs font-mono text-amber-300 font-medium">
              Notice: Not a CTF
            </span>
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-400 font-medium">
              Vigil-SOC v0.6.0
            </span>
          </div>

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold text-white tracking-tight leading-tight">
            Agents Hunting Agents
          </h1>
          <p className="text-slate-300 text-sm sm:text-base md:text-lg max-w-3xl leading-relaxed">
            Welcome to the onboarding guide for tomorrow&apos;s session. This is an exploratory hands-on learning lab—not a competitive CTF. We are setting up <strong className="text-cyan-400">Vigil-SOC + LogLM</strong> from scratch on your local machine to hunt telemetry datasets with local autonomous AI agents.
          </p>

          <div className="pt-2 flex flex-wrap items-center gap-3">
            <a
              href="https://drive.google.com/file/d/1xGzvY1SzwFA3qJ-3bduQAduDYUFpe7mi/view?usp=sharing"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm transition-all shadow-lg shadow-cyan-500/25 font-mono"
            >
              <Download className="w-4 h-4" />
              Download Dataset Archive (10 MB)
            </a>
            <a
              href="#checklist"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 font-medium text-sm transition-colors font-mono"
            >
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Done Means Checklist ({completedCount}/6)
            </a>
            <a
              href="#report"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 font-medium text-sm transition-colors font-mono"
            >
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              Report Back Generator
            </a>
          </div>
        </div>
      </div>

      {/* Overview & Goal Callout */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono font-semibold">
            <Laptop className="w-4 h-4" />
            <span>THE ASK</span>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            Run the attendee setup guide end-to-end on your own laptop before the workshop begins, and report back your results and friction points in the thread.
          </p>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-semibold">
            <ShieldCheck className="w-4 h-4" />
            <span>HANDS-ON LEARNING</span>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            It&apos;s our own platform: each participant will experience setting up Vigil + LogLM, importing findings, and watching local AI agents triage threats.
          </p>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
          <div className="flex items-center gap-2 text-amber-400 text-xs font-mono font-semibold">
            <AlertTriangle className="w-4 h-4" />
            <span>SURFACING FRICTION</span>
          </div>
          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
            Any hiccup or friction you encounter on your machine is something attendees will hit too. Testing across Mac (Intel/Silicon), Linux, and Windows is essential.
          </p>
        </div>
      </div>

      {/* Mac Silicon Special Warning Alert */}
      <div className="rounded-xl border border-amber-500/40 bg-amber-950/20 p-4 sm:p-5 flex items-start gap-4">
        <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 shrink-0">
          <AlertTriangle className="w-5 h-5" />
        </div>
        <div className="space-y-1 text-xs sm:text-sm">
          <h3 className="font-bold text-amber-300 font-mono flex items-center gap-2">
            Apple Silicon & macOS Attention Point: 32k Ollama Context
          </h3>
          <p className="text-slate-300 leading-relaxed">
            Mac users on Apple Silicon (M1/M2/M3/M4): the <code className="text-amber-300 bg-amber-950/60 px-1 py-0.5 rounded border border-amber-800/50">32k Ollama context window</code> step on macOS has not been thoroughly verified across all macOS versions yet. Please test this step carefully and let us know your exact RAM and execution behavior!
          </p>
        </div>
      </div>

      {/* Done Means Tracker */}
      <div id="checklist" className="rounded-2xl border border-slate-800 bg-slate-900/40 p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span>&ldquo;Done Means&rdquo; Checklist</span>
            </h2>
            <p className="text-xs text-slate-400">
              Check off each milestone as you complete it. Your progress is saved locally.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-xs font-mono text-slate-400">READINESS</div>
              <div className="text-lg font-bold font-mono text-cyan-400">{progressPct}%</div>
            </div>
            <div className="w-24 bg-slate-800 rounded-full h-2.5 overflow-hidden border border-slate-700">
              <div
                className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-2.5 rounded-full transition-all duration-300"
                style={{ width: `${progressPct}%` }}
              ></div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {CHECKLIST_ITEMS.map((item) => {
            const isDone = !!completed[item.id];
            return (
              <div
                key={item.id}
                onClick={() => toggleCheck(item.id)}
                className={`p-4 rounded-xl border cursor-pointer transition-all flex items-start gap-3 select-none ${
                  isDone
                    ? 'border-emerald-500/50 bg-emerald-950/20 text-slate-200'
                    : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 text-slate-300'
                }`}
              >
                <button
                  type="button"
                  className="mt-0.5 text-slate-400 hover:text-white transition-colors"
                  aria-label={`Toggle ${item.title}`}
                >
                  {isDone ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 fill-emerald-500/20" />
                  ) : (
                    <Circle className="w-5 h-5 text-slate-600" />
                  )}
                </button>
                <div className="space-y-1 flex-1">
                  <div className="flex items-center justify-between">
                    <span className={`text-sm font-semibold ${isDone ? 'text-emerald-300' : 'text-white'}`}>
                      {item.title}
                    </span>
                    {item.category === 'bonus' && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                        Bonus
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400">{item.description}</p>
                  <div className="pt-1 text-[11px] font-mono text-cyan-300/80 bg-slate-900/80 px-2 py-1 rounded border border-slate-800 flex items-center justify-between">
                    <span className="truncate">Expected: {item.expected}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Step by Step Walkthrough */}
      <div className="space-y-6">
        <div className="border-b border-slate-800 pb-2 flex items-center justify-between">
          <h2 className="text-lg font-bold text-white font-mono tracking-wide uppercase flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>End-to-End Installation & Setup Guide</span>
          </h2>
          <span className="text-xs font-mono text-slate-400">Step 1 to 6</span>
        </div>

        {/* Step 1: Docker */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center font-mono text-xs">
                1
              </span>
              <span>Verify Docker Engine</span>
            </div>
            <span className="text-xs font-mono text-slate-400">Prerequisite</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Ensure Docker Desktop (macOS / Windows) or Docker Engine (Linux) is running and responsive from your terminal:
          </p>
          <div className="relative group rounded-lg bg-slate-950 border border-slate-800 p-3 font-mono text-xs text-cyan-300 flex items-center justify-between">
            <code>docker run --rm hello-world</code>
            <button
              onClick={() => handleCopy('docker run --rm hello-world', 'step1')}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
              title="Copy command"
            >
              {copiedKey === 'step1' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-[11px] text-slate-400 font-mono">
            ✔ Expected: Prints &ldquo;Hello from Docker!&rdquo; and exits cleanly.
          </p>
        </div>

        {/* Step 2: Ollama & Models */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center font-mono text-xs">
                2
              </span>
              <span>Install Ollama & Pull Qwen2.5 Model</span>
            </div>
            <span className="text-xs font-mono text-slate-400">Local AI Engine</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Vigil-SOC uses local LLMs via Ollama to perform autonomous threat analysis and tool calling. Select the model based on your system RAM:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {/* Standard 16GB+ */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-bold text-cyan-400 font-mono">
                <span>Standard (16 GB+ RAM)</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                  Recommended
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Run Qwen2.5 3B with single-word verification test:
              </p>
              <div className="relative group rounded bg-slate-900 border border-slate-800/80 p-2 font-mono text-xs text-slate-200 flex items-center justify-between">
                <code className="text-emerald-300">ollama run qwen2.5:3b &quot;Reply with one word: ready&quot;</code>
                <button
                  onClick={() => handleCopy('ollama run qwen2.5:3b "Reply with one word: ready"', 'qwen3b')}
                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  {copiedKey === 'qwen3b' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {/* 8GB RAM Laptops */}
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-bold text-amber-400 font-mono">
                <span>Lightweight (8 GB RAM)</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-950 border border-amber-800 text-amber-300">
                  Low Memory
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Run Qwen2.5 1.5B for laptops with constrained memory:
              </p>
              <div className="relative group rounded bg-slate-900 border border-slate-800/80 p-2 font-mono text-xs text-slate-200 flex items-center justify-between">
                <code className="text-amber-300">ollama run qwen2.5:1.5b &quot;Reply with one word: ready&quot;</code>
                <button
                  onClick={() => handleCopy('ollama run qwen2.5:1.5b "Reply with one word: ready"', 'qwen1b')}
                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  {copiedKey === 'qwen1b' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          </div>

          {/* 32k Context Setup Callout */}
          <div className="p-3 rounded-lg bg-slate-950/80 border border-amber-500/30 space-y-2 text-xs">
            <div className="flex items-center gap-2 text-amber-400 font-mono font-semibold">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>32k Context Window Configuration (Ollama)</span>
            </div>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              To support long forensic timelines and multi-step tool calls, set Ollama&apos;s context length to 32k tokens. On macOS/Linux, set the environment variable or create a custom Modelfile:
            </p>
            <div className="rounded bg-slate-900 p-2 font-mono text-[11px] text-cyan-300 flex items-center justify-between border border-slate-800">
              <code>OLLAMA_NUM_CTX=32768 ollama serve</code>
              <button
                onClick={() => handleCopy('OLLAMA_NUM_CTX=32768 ollama serve', 'ollama_ctx')}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                {copiedKey === 'ollama_ctx' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        {/* Step 3: Launching Vigil-SOC & Setting Model */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center font-mono text-xs">
                3
              </span>
              <span>Launch Vigil-SOC & Assign AI Model</span>
            </div>
            <span className="text-xs font-mono text-slate-400">Vigil v0.6.0</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Access your running Vigil instance at <code className="text-cyan-400 bg-slate-950 px-1 py-0.5 rounded border border-slate-800">localhost:6987</code> (or your configured port).
          </p>
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs">
            <div className="font-mono text-slate-200 font-semibold flex items-center gap-2">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <span>Model Assignment Path:</span>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-emerald-300 bg-slate-900/90 p-2 rounded border border-slate-800">
              <span>Settings</span>
              <span className="text-slate-500">→</span>
              <span>AI Config</span>
              <span className="text-slate-500">→</span>
              <span>Model Assignment</span>
              <span className="text-slate-500">→</span>
              <span className="text-cyan-300">Select &quot;qwen2.5:3b&quot; (or 1.5b)</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Confirm the model endpoint points to <code className="text-slate-300">http://host.docker.internal:11434</code> (if running inside container) or <code className="text-slate-300">http://localhost:11434</code> (if running natively).
            </p>
          </div>
        </div>

        {/* Step 4: Dataset Download */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center font-mono text-xs">
                4
              </span>
              <span>Download & Verify Dataset Archive (10 MB)</span>
            </div>
            <span className="text-xs font-mono text-slate-400">Telemetry Data</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Download the hunting dataset package containing sample attack traces and LogLM parquet files:
          </p>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 p-3 rounded-lg bg-slate-950 border border-slate-800">
            <div className="flex-1 space-y-1">
              <div className="text-xs font-mono font-semibold text-slate-200">
                Google Drive Hunting Dataset (~10 MB)
              </div>
              <div className="text-[11px] text-slate-400 truncate">
                Contains: loglm-findings.parquet, evidence logs, and synthetic traces
              </div>
            </div>
            <a
              href="https://drive.google.com/file/d/1xGzvY1SzwFA3qJ-3bduQAduDYUFpe7mi/view?usp=sharing"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition-colors font-mono shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              Download via Drive
            </a>
          </div>
          <p className="text-[11px] text-slate-400 font-mono">
            ✔ Unpack the archive and verify <code className="text-slate-300">loglm-findings.parquet</code> exists in the uncompressed folder.
          </p>
        </div>

        {/* Step 5: LogLM Upload */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 flex items-center justify-center font-mono text-xs">
                5
              </span>
              <span>Upload LogLM Findings Parquet</span>
            </div>
            <span className="text-xs font-mono text-slate-400">Ingest Verification</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            In the Vigil web interface, navigate to the Findings / Ingestion section and upload <code className="text-cyan-300 bg-slate-950 px-1 py-0.5 rounded border border-slate-800">loglm-findings.parquet</code>.
          </p>
          <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/40 flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div className="text-xs font-mono text-emerald-300">
              Expected Confirmation: <strong className="text-white">&ldquo;Imported 256 findings&rdquo;</strong>
            </div>
          </div>
        </div>

        {/* Step 6: Bonus Verification */}
        <div className="rounded-xl border border-purple-500/30 bg-purple-950/10 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span className="w-6 h-6 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 flex items-center justify-center font-mono text-xs">
                6
              </span>
              <span>Bonus: Test Socratic Chat & Tool Calling</span>
            </div>
            <span className="text-xs font-mono text-purple-300">Autonomous Agent</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Open the Vigil Chat interface and ask questions about the newly imported findings. Observe whether the local model autonomously calls tools to query the dataset:
          </p>
          <div className="space-y-2">
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 flex items-center justify-between">
              <span>&ldquo;Analyze the LogLM imported findings for high-severity anomalies or lateral movement.&rdquo;</span>
              <button
                onClick={() => handleCopy('Analyze the LogLM imported findings for high-severity anomalies or lateral movement.', 'prompt1')}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                {copiedKey === 'prompt1' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 flex items-center justify-between">
              <span>&ldquo;Which IP addresses or services are associated with repeated credential failure findings?&rdquo;</span>
              <button
                onClick={() => handleCopy('Which IP addresses or services are associated with repeated credential failure findings?', 'prompt2')}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                {copiedKey === 'prompt2' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
          <p className="text-[11px] text-purple-300/80 font-mono">
            ✔ Verify that the agent generates tool calls (e.g. searching findings table, filtering by severity) before synthesizing its answer.
          </p>
        </div>
      </div>

      {/* Attendee Report Generator */}
      <div id="report" className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-6">
        <div className="border-b border-slate-800 pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="space-y-1">
            <h2 className="text-lg font-bold text-white font-mono uppercase flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              <span>Attendee Readiness Report Generator</span>
            </h2>
            <p className="text-xs text-slate-400">
              Fill in your hardware specs and friction details, then copy your formatted update for the thread.
            </p>
          </div>
          <button
            onClick={copyReport}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors shadow-lg shadow-cyan-500/20"
          >
            {reportCopied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {reportCopied ? 'Copied to Clipboard!' : 'Copy Report for Thread'}
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
          {/* OS Selector */}
          <div className="space-y-1.5">
            <label className="text-slate-400 font-semibold">Operating System</label>
            <select
              value={osName}
              onChange={(e) => setOsName(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="macOS Apple Silicon (M1/M2/M3/M4)">macOS Apple Silicon (M1/M2/M3/M4)</option>
              <option value="macOS Intel">macOS Intel</option>
              <option value="Ubuntu / Debian Linux">Ubuntu / Debian Linux</option>
              <option value="Fedora / Arch Linux">Fedora / Arch Linux</option>
              <option value="Windows 11 (WSL2)">Windows 11 (WSL2)</option>
              <option value="Other Linux">Other Linux</option>
            </select>
          </div>

          {/* RAM Size */}
          <div className="space-y-1.5">
            <label className="text-slate-400 font-semibold">System Memory (RAM)</label>
            <select
              value={ramSize}
              onChange={(e) => setRamSize(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="8 GB">8 GB (qwen2.5:1.5b)</option>
              <option value="16 GB">16 GB (qwen2.5:3b)</option>
              <option value="24 GB">24 GB</option>
              <option value="32 GB">32 GB</option>
              <option value="64 GB+">64 GB+</option>
            </select>
          </div>

          {/* Model Chosen */}
          <div className="space-y-1.5">
            <label className="text-slate-400 font-semibold">Ollama Model Used</label>
            <select
              value={modelChosen}
              onChange={(e) => setModelChosen(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="qwen2.5:3b">qwen2.5:3b (Standard)</option>
              <option value="qwen2.5:1.5b">qwen2.5:1.5b (8 GB RAM)</option>
              <option value="qwen2.5:7b">qwen2.5:7b (Large)</option>
              <option value="Other">Other</option>
            </select>
          </div>

          {/* Duration */}
          <div className="space-y-1.5">
            <label className="text-slate-400 font-semibold">Time to Complete</label>
            <input
              type="text"
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              placeholder="e.g. 20 mins"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Overall Status */}
          <div className="space-y-1.5">
            <label className="text-slate-400 font-semibold">Overall Outcome</label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setStatusResult('success')}
                className={`py-2 px-3 rounded-lg border text-center transition-all ${
                  statusResult === 'success'
                    ? 'border-emerald-500 bg-emerald-950/40 text-emerald-300 font-bold'
                    : 'border-slate-800 bg-slate-950 text-slate-400'
                }`}
              >
                ✔ All Done
              </button>
              <button
                type="button"
                onClick={() => setStatusResult('stuck')}
                className={`py-2 px-3 rounded-lg border text-center transition-all ${
                  statusResult === 'stuck'
                    ? 'border-rose-500 bg-rose-950/40 text-rose-300 font-bold'
                    : 'border-slate-800 bg-slate-950 text-slate-400'
                }`}
              >
                ⚠️ Stuck / Friction
              </button>
            </div>
          </div>

          {/* Mac 32k context tested */}
          <div className="space-y-1.5">
            <label className="text-slate-400 font-semibold">Mac 32k Context Step</label>
            <select
              value={mac32kTested}
              onChange={(e) => setMac32kTested(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="Tested OK (32k context responded)">Tested OK (32k context responded)</option>
              <option value="Hit issue / OOM on 32k">Hit issue / OOM on 32k</option>
              <option value="Not applicable (Non-Mac)">Not applicable (Non-Mac)</option>
              <option value="Skipped / Standard 4k">Skipped / Standard 4k</option>
            </select>
          </div>
        </div>

        {/* Friction notes textarea */}
        <div className="space-y-1.5">
          <label className="text-xs font-mono text-slate-400 font-semibold flex items-center justify-between">
            <span>Friction Points / Where You Got Stuck / Notes:</span>
            <span className="text-[11px] text-slate-500">Every detail helps tomorrow&apos;s attendees</span>
          </label>
          <textarea
            rows={3}
            value={notesFriction}
            onChange={(e) => setNotesFriction(e.target.value)}
            placeholder="Describe any friction, port conflicts, slow model downloads, or UI confusion..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          ></textarea>
        </div>

        {/* Live Preview Box */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>PREVIEW (WHAT GETS COPIED TO SLACK / THREAD)</span>
            <button
              onClick={copyReport}
              className="text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1"
            >
              {reportCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{reportCopied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 whitespace-pre-wrap select-all overflow-x-auto leading-relaxed">
            {generateReportText()}
          </pre>
        </div>
      </div>

      {/* Helpful FAQ / Quick Reference */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-5 space-y-4">
        <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
          <HelpCircle className="w-4 h-4 text-cyan-400" />
          <span>Workshop Quick FAQ & Troubleshooting</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-300">
          <div className="space-y-1 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
            <h4 className="font-bold text-slate-200">Why is this event not a CTF?</h4>
            <p className="text-slate-400 leading-relaxed">
              CTFs focus on competitive puzzle solving and finding synthetic flags. Tomorrow&apos;s session is an engineering and operations deep-dive: learning how to set up, operate, and utilize Vigil-SOC and LogLM to hunt real telemetry and understand how AI agents reason.
            </p>
          </div>

          <div className="space-y-1 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
            <h4 className="font-bold text-slate-200">What if my laptop only has 8 GB RAM?</h4>
            <p className="text-slate-400 leading-relaxed">
              Use <code className="text-amber-300">qwen2.5:1.5b</code>. It consumes under 2 GB of VRAM/system memory and still performs well with Vigil&apos;s function calling and finding classification pipelines.
            </p>
          </div>

          <div className="space-y-1 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
            <h4 className="font-bold text-slate-200">Port 6987 or Localhost Issues?</h4>
            <p className="text-slate-400 leading-relaxed">
              Check if another container or service is occupying port 6987 using <code className="text-slate-300">lsof -i :6987</code> or <code className="text-slate-300">docker ps</code>. Vigil-SOC can also be started with custom port mapping in your configuration.
            </p>
          </div>

          <div className="space-y-1 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
            <h4 className="font-bold text-slate-200">Why LogLM Parquet?</h4>
            <p className="text-slate-400 leading-relaxed">
              LogLM generates structured security findings stored in Parquet format. Importing the 256 findings seeds your local Vigil instance with rich security telemetry ready for triage.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
