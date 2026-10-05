'use client';

import React, { useState, useEffect } from 'react';
import {
  Flag,
  Play,
  Terminal,
  Clock,
  ExternalLink,
  Shield,
  HelpCircle,
  AlertOctagon,
  Copy,
  Check,
  CheckCircle2,
  RefreshCw,
  Sparkles
} from 'lucide-react';

export default function CTFArenaPage() {
  const [categories, setCategories] = useState<any[]>([]);
  const [challenges, setChallenges] = useState<any[]>([]);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [sandboxes, setSandboxes] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedChallenge, setSelectedChallenge] = useState<any>(null);
  const [flagInput, setFlagInput] = useState<string>('');
  const [submitFeedback, setSubmitFeedback] = useState<any>(null);

  // Socratic Mentor modal state
  const [mentorOpen, setMentorOpen] = useState<boolean>(false);
  const [mentorTier, setMentorTier] = useState<number>(1);
  const [mentorQuestion, setMentorQuestion] = useState<string>('');
  const [mentorResult, setMentorResult] = useState<any>(null);
  const [mentorLoading, setMentorLoading] = useState<boolean>(false);

  // Crash analyzer modal state
  const [crashLog, setCrashLog] = useState<string>('');
  const [crashDiagnosis, setCrashDiagnosis] = useState<any>(null);

  // Fetch challenges and active sandboxes
  useEffect(() => {
    fetch('/api/ctf/challenges')
      .then((res) => res.json())
      .then((data) => {
        setCategories(data.categories || []);
        setChallenges(data.challenges || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));

    fetch('/api/ctf/sandboxes')
      .then((res) => res.json())
      .then((data) => setSandboxes(data.sandboxes || []))
      .catch(() => {});
  }, []);

  const handleSpawnSandbox = async (challengeId: string) => {
    try {
      const res = await fetch('/api/ctf/sandboxes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId, teamId: 'web-operator', ttlMinutes: 30 })
      });
      const data = await res.json();
      if (data.success) {
        // Refresh sandboxes
        const listRes = await fetch('/api/ctf/sandboxes');
        const listData = await listRes.json();
        setSandboxes(listData.sandboxes || []);
      }
    } catch {
      // Ignore
    }
  };

  const handleAskMentor = async () => {
    setMentorLoading(true);
    try {
      const res = await fetch('/api/ctf/mentor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'hint',
          tier: mentorTier,
          userQuery: mentorQuestion,
          challengeId: selectedChallenge?.id
        })
      });
      const data = await res.json();
      setMentorResult(data.hint);
    } catch {
      // Ignore
    } finally {
      setMentorLoading(false);
    }
  };

  const handleAnalyzeCrash = async () => {
    if (!crashLog) return;
    try {
      const res = await fetch('/api/ctf/mentor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'crash',
          crashLog,
          challengeId: selectedChallenge?.id
        })
      });
      const data = await res.json();
      setCrashDiagnosis(data.diagnosis);
    } catch {
      // Ignore
    }
  };

  const filteredChals = challenges.filter((c) => {
    if (activeCategory === 'all') return true;
    return c.category === activeCategory;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
            <Flag className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              kCTF Cyber Range & Arena
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 border border-amber-800 text-amber-300">
                Jeopardy · Attack-Defense · KotH
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Ephemeral pod sandboxes running in Kubernetes namespace <code>ctf-sandboxes</code> with automated Traefik ingress routing.
            </p>
          </div>
        </div>

        {/* Active Sandboxes Badge */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Active Sandboxes: <strong className="text-white">{sandboxes.length}/3</strong></span>
        </div>
      </div>

      {/* Category Filter Pills */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 pb-3">
        <button
          onClick={() => setActiveCategory('all')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
            activeCategory === 'all'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
              : 'bg-slate-900/60 text-slate-400 hover:text-white border border-slate-800'
          }`}
        >
          All Categories ({challenges.length})
        </button>
        {categories.map((cat) => (
          <button
            key={cat.id}
            onClick={() => setActiveCategory(cat.id)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 transition-colors ${
              activeCategory === cat.id
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                : 'bg-slate-900/60 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <span>{cat.icon}</span>
            <span>{cat.name}</span>
          </button>
        ))}
      </div>

      {/* Challenges Grid & Active Sandbox List */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredChals.map((chal) => {
          const activeSbx = sandboxes.find((s) => s.challengeId === chal.id);

          return (
            <div
              key={chal.id}
              className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 flex flex-col justify-between space-y-4 hover:border-slate-700 transition-all group"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                    chal.difficulty === 'Easy' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                    chal.difficulty === 'Medium' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    'bg-rose-950 text-rose-300 border border-rose-800'
                  }`}>
                    {chal.difficulty}
                  </span>
                  <span className="text-xs font-mono text-cyan-400">{chal.protocol}:{chal.port}</span>
                </div>

                <h3 className="text-base font-bold text-white group-hover:text-amber-400 transition-colors">
                  {chal.name}
                </h3>
                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                  {chal.description}
                </p>
              </div>

              {/* Active Sandbox info or Launch button */}
              <div className="pt-3 border-t border-slate-800/80 space-y-2">
                {activeSbx ? (
                  <div className="space-y-1.5 p-2.5 rounded-lg bg-cyan-950/30 border border-cyan-800/60 text-xs font-mono">
                    <div className="flex items-center justify-between text-cyan-300 font-bold">
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                        ONLINE
                      </span>
                      <span>TTL: {activeSbx.remainingMinutes || 30}m</span>
                    </div>
                    <a
                      href={activeSbx.connectionUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1 truncate"
                    >
                      <ExternalLink className="w-3 h-3 shrink-0" />
                      <span className="truncate">{activeSbx.connectionUrl}</span>
                    </a>
                  </div>
                ) : (
                  <button
                    onClick={() => handleSpawnSandbox(chal.id)}
                    className="w-full flex items-center justify-center gap-2 py-2 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-mono font-semibold transition-colors"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Spawn Isolated Pod</span>
                  </button>
                )}

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setSelectedChallenge(chal);
                      setMentorOpen(true);
                    }}
                    className="flex-1 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center justify-center gap-1 transition-colors"
                  >
                    <HelpCircle className="w-3 h-3 text-cyan-400" />
                    <span>Socratic Hint</span>
                  </button>
                  <button
                    onClick={() => {
                      setSelectedChallenge(chal);
                      setCrashDiagnosis(null);
                    }}
                    className="flex-1 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-slate-300 flex items-center justify-center gap-1 transition-colors"
                  >
                    <Terminal className="w-3 h-3 text-purple-400" />
                    <span>Crash Triage</span>
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Socratic Mentor Modal / Drawer */}
      {mentorOpen && selectedChallenge && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-xl bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-white text-base">
                  3-Tier Socratic AI Mentor: {selectedChallenge.name}
                </h3>
              </div>
              <button
                onClick={() => setMentorOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>

            {/* Tier Selector */}
            <div className="grid grid-cols-3 gap-2 text-xs font-mono">
              {[
                { tier: 1, name: 'Tier 1: Recon', penalty: '0% Penalty' },
                { tier: 2, name: 'Tier 2: Probes', penalty: '10% Penalty' },
                { tier: 3, name: 'Tier 3: Tools', penalty: '25% Penalty' }
              ].map((t) => (
                <button
                  key={t.tier}
                  onClick={() => setMentorTier(t.tier)}
                  className={`p-2.5 rounded-lg border text-center transition-colors ${
                    mentorTier === t.tier
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50'
                      : 'bg-slate-900 border-slate-800 text-slate-400'
                  }`}
                >
                  <div className="font-bold">{t.name}</div>
                  <div className="text-[10px] text-slate-500">{t.penalty}</div>
                </button>
              ))}
            </div>

            <div className="space-y-1">
              <label className="text-xs font-mono text-slate-400">Describe what you observe or where you are stuck:</label>
              <textarea
                value={mentorQuestion}
                onChange={(e) => setMentorQuestion(e.target.value)}
                placeholder="e.g. When I send a format string, what register holds the parameter?"
                className="w-full h-20 bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 outline-none focus:border-cyan-500"
              />
            </div>

            <button
              onClick={handleAskMentor}
              disabled={mentorLoading}
              className="w-full py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors disabled:opacity-50"
            >
              {mentorLoading ? 'Querying Socratic Engine...' : 'Unlock Socratic Guidance'}
            </button>

            {mentorResult && (
              <div className="p-4 rounded-xl bg-slate-900/80 border border-cyan-800/50 space-y-2 text-xs font-mono">
                <div className="text-cyan-400 font-bold flex items-center justify-between">
                  <span>Mentor Insight (Penalty: {mentorResult.penaltyPercent}%)</span>
                  <span>{mentorResult.tierName}</span>
                </div>
                <div className="text-slate-300 leading-relaxed whitespace-pre-wrap">
                  {mentorResult.guidance}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
