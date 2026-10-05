'use client';

import React, { useState } from 'react';
import {
  Cpu,
  Terminal,
  Send,
  Sparkles,
  AlertTriangle,
  Flame,
  CheckCircle2,
  RefreshCw,
  Users
} from 'lucide-react';

export default function AnalystPage() {
  const [messages, setMessages] = useState<any[]>([
    {
      role: 'assistant',
      content: 'Welcome to the Socratic AI Security Analyst console. I enforce strict educational tournament guardrails: zero flag leaks and zero weaponized exploit generation. Paste a GDB crash dump, reverse engineering question, or security query to begin.'
    }
  ]);
  const [inputQuery, setInputQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [provider, setProvider] = useState<string>('ollama');

  const [crashDump, setCrashDump] = useState<string>('Program received signal SIGSEGV, Segmentation fault.\n$rip: 0x0000000041346141\n$rsp: 0x00007fffffffe100\n$rbp: 0x4141414141414141');
  const [crashResult, setCrashResult] = useState<any>(null);

  const handleSend = async () => {
    if (!inputQuery.trim()) return;
    const userMsg = { role: 'user', content: inputQuery };
    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const res = await fetch('/api/ctf/mentor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'hint', tier: 2, userQuery: inputQuery })
      });
      const data = await res.json();
      const botMsg = {
        role: 'assistant',
        content: data.hint?.guidance || 'Methodology probe: What happens to input data before validation? Check memory alignments and verify buffer bounds.'
      };
      setMessages((prev) => [...prev, botMsg]);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  };

  const handleDiagnoseCrash = async () => {
    if (!crashDump) return;
    try {
      const res = await fetch('/api/ctf/mentor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'crash', crashLog: crashDump })
      });
      const data = await res.json();
      setCrashResult(data.diagnosis);
    } catch {
      // Ignore
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Socratic AI Analyst & Multi-Agent War Room
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                Guardrails Active · Zero Flag Leaks
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Interactive pedagogical guidance, root cause crash disassembly, and multi-agent incident consensus.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-mono">
          <span className="px-2 text-slate-500">Provider:</span>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="bg-slate-950 text-slate-200 border-none outline-none text-xs rounded px-2 py-1"
          >
            <option value="ollama">Ollama (Local Offline)</option>
            <option value="claude">Claude 3.5 Sonnet</option>
            <option value="openai">GPT-4o</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[500px]">
        {/* Left: Chat Console */}
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5 flex flex-col justify-between space-y-4">
          <div className="text-xs font-mono font-bold text-slate-300 border-b border-slate-800 pb-2 flex items-center justify-between">
            <span>Socratic Conversation</span>
            <span className="text-cyan-400">Strict Mentor Mode</span>
          </div>

          <div className="flex-1 space-y-3 overflow-y-auto max-h-[380px] p-2">
            {messages.map((m, i) => (
              <div
                key={i}
                className={`p-3 rounded-xl text-xs font-mono leading-relaxed ${
                  m.role === 'assistant'
                    ? 'bg-slate-900/80 border border-slate-800 text-slate-200'
                    : 'bg-cyan-950/40 border border-cyan-800/60 text-cyan-200 ml-6'
                }`}
              >
                <div className="text-[10px] text-slate-500 pb-1 font-bold">
                  {m.role === 'assistant' ? '🤖 SOCRATIC MENTOR' : '👤 OPERATOR'}
                </div>
                {m.content}
              </div>
            ))}
          </div>

          {/* Input bar */}
          <div className="flex items-center gap-2 pt-2 border-t border-slate-800">
            <input
              type="text"
              placeholder="Ask an investigative or methodology question..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-cyan-500"
            />
            <button
              onClick={handleSend}
              disabled={loading}
              className="p-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors disabled:opacity-50"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Right: GDB Crash Context Analyzer */}
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5 flex flex-col justify-between space-y-4">
          <div className="text-xs font-mono font-bold text-slate-300 border-b border-slate-800 pb-2 flex items-center justify-between">
            <span>GDB Crash Log & De Bruijn Offset Parser</span>
            <Terminal className="w-4 h-4 text-purple-400" />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-mono text-slate-400">Paste GDB crash registers, fault address, or traceback:</label>
            <textarea
              value={crashDump}
              onChange={(e) => setCrashDump(e.target.value)}
              rows={4}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs font-mono text-purple-300 outline-none focus:border-purple-500"
            />
            <button
              onClick={handleDiagnoseCrash}
              className="w-full py-2 rounded-lg bg-purple-500 hover:bg-purple-400 text-slate-950 font-bold text-xs font-mono transition-colors"
            >
              Diagnose Crash Root Cause & Calculate Cyclic Offset
            </button>
          </div>

          {crashResult && (
            <div className="p-4 rounded-xl bg-purple-950/30 border border-purple-800/60 text-xs font-mono space-y-2">
              <div className="flex items-center justify-between text-purple-300 font-bold">
                <span>Signal: {crashResult.signal}</span>
                <span>Type: {crashResult.crashType}</span>
              </div>
              <div className="text-slate-300">
                Fault Address: <code className="text-cyan-400">{crashResult.faultAddress || 'N/A'}</code>
              </div>
              {crashResult.deBruijnOffset !== null && (
                <div className="text-emerald-400 font-bold">
                  ✔ Exact Cyclic Offset: {crashResult.deBruijnOffset} bytes
                </div>
              )}
              <div className="pt-2 border-t border-purple-900/60 space-y-1">
                <span className="text-slate-400 font-semibold">Socratic Probing Questions:</span>
                {(crashResult.socraticQuestions || []).map((q: string, i: number) => (
                  <div key={i} className="text-slate-300 text-[11px]">• {q}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
