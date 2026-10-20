'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
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
  Sparkles,
  BookOpen,
  Trophy,
  Flame,
  Send,
  X,
  Trash2,
  Zap,
  RotateCcw
} from 'lucide-react';

export default function CTFArenaPage() {
  const [activeTab, setActiveTab] = useState<'arena' | 'scoreboard'>('arena');
  const [categories, setCategories] = useState<any[]>([]);
  const [challenges, setChallenges] = useState<any[]>([]);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [sandboxes, setSandboxes] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedChallenge, setSelectedChallenge] = useState<any>(null);

  // Per-challenge flag input states: { [chalId]: string }
  const [flagInputs, setFlagInputs] = useState<Record<string, string>>({});
  const [submitFeedback, setSubmitFeedback] = useState<Record<string, { success: boolean; message: string; points?: number; badge?: string }>>({});
  const [submitting, setSubmitting] = useState<Record<string, boolean>>({});

  // Socratic Mentor modal state
  const [mentorOpen, setMentorOpen] = useState<boolean>(false);
  const [mentorTier, setMentorTier] = useState<number>(1);
  const [mentorQuestion, setMentorQuestion] = useState<string>('');
  const [mentorResult, setMentorResult] = useState<any>(null);
  const [mentorLoading, setMentorLoading] = useState<boolean>(false);

  // Crash analyzer modal state
  const [crashModalOpen, setCrashModalOpen] = useState<boolean>(false);
  const [crashLog, setCrashLog] = useState<string>('');
  const [crashDiagnosis, setCrashDiagnosis] = useState<any>(null);
  const [crashLoading, setCrashLoading] = useState<boolean>(false);

  // Scoreboard state
  const [scoreboardData, setScoreboardData] = useState<any>(null);
  const [scoreboardLoading, setScoreboardLoading] = useState<boolean>(false);

  // Team identity
  const [teamName, setTeamName] = useState<string>('Vigilante Operative');

  const fetchChallenges = () => {
    return fetch('/api/ctf/challenges')
      .then((res) => res.json())
      .then((data) => {
        setCategories(data.categories || []);
        setChallenges(data.challenges || []);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  const fetchSandboxes = () => {
    return fetch('/api/ctf/sandboxes')
      .then((res) => res.json())
      .then((data) => setSandboxes(data.sandboxes || []))
      .catch(() => {});
  };

  const fetchScoreboard = () => {
    setScoreboardLoading(true);
    fetch('/api/ctf/scoreboard')
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          setScoreboardData(data);
        }
      })
      .finally(() => setScoreboardLoading(false));
  };

  useEffect(() => {
    fetchChallenges();
    fetchSandboxes();
  }, []);

  useEffect(() => {
    if (activeTab === 'scoreboard') {
      fetchScoreboard();
    }
  }, [activeTab]);

  const handleSpawnSandbox = async (challengeId: string) => {
    try {
      const res = await fetch('/api/ctf/sandboxes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId, teamId: teamName.toLowerCase().replace(/[^a-z0-9]/g, '-'), ttlMinutes: 30 })
      });
      const data = await res.json();
      if (data.success) {
        await fetchSandboxes();
      }
    } catch {
      // Ignore
    }
  };

  const handleExtendSandbox = async (sandboxId: string) => {
    try {
      const res = await fetch('/api/ctf/sandboxes', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'extend', sandboxId, additionalMinutes: 15 })
      });
      const data = await res.json();
      if (data.success) {
        await fetchSandboxes();
      }
    } catch {
      // Ignore
    }
  };

  const handleTerminateSandbox = async (sandboxId: string) => {
    try {
      const res = await fetch(`/api/ctf/sandboxes?sandboxId=${encodeURIComponent(sandboxId)}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (data.success) {
        await fetchSandboxes();
      }
    } catch {
      // Ignore
    }
  };

  const handleReapSandboxes = async () => {
    try {
      const res = await fetch('/api/ctf/sandboxes', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'reap' })
      });
      const data = await res.json();
      if (data.success) {
        await fetchSandboxes();
      }
    } catch {
      // Ignore
    }
  };

  const handleSubmitFlag = async (challengeId: string) => {
    const flag = (flagInputs[challengeId] || '').trim();
    if (!flag) return;

    setSubmitting((prev) => ({ ...prev, [challengeId]: true }));
    setSubmitFeedback((prev) => ({ ...prev, [challengeId]: null as any }));

    try {
      const res = await fetch('/api/ctf/challenges', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId,
          flag,
          teamName,
          teamId: teamName.toLowerCase().replace(/[^a-z0-9]/g, '-')
        })
      });
      const data = await res.json();

      if (data.success) {
        setSubmitFeedback((prev) => ({
          ...prev,
          [challengeId]: {
            success: true,
            message: `Flag Captured! +${data.points} pts${data.bloodBadge ? ` ${data.bloodBadge} First Blood!` : ''}`,
            points: data.points,
            badge: data.bloodBadge
          }
        }));
        // Refresh challenges to update points and solved status
        await fetchChallenges();
      } else {
        setSubmitFeedback((prev) => ({
          ...prev,
          [challengeId]: {
            success: false,
            message: data.reason || data.error || 'Incorrect flag submitted.'
          }
        }));
      }
    } catch (err: any) {
      setSubmitFeedback((prev) => ({
        ...prev,
        [challengeId]: {
          success: false,
          message: err.message || 'Submission network error.'
        }
      }));
    } finally {
      setSubmitting((prev) => ({ ...prev, [challengeId]: false }));
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
    setCrashLoading(true);
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
    } finally {
      setCrashLoading(false);
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

        {/* Actions & Navigation */}
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href="/event"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-cyan-500/30 text-cyan-300 text-xs font-mono transition-colors"
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Player Guide & Tools</span>
          </Link>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Active Sandboxes: <strong className="text-white">{sandboxes.length}/3</strong></span>
          </div>
        </div>
      </div>

      {/* Navigation Tabs (Arena vs Scoreboard) */}
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-1">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('arena')}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg font-mono text-xs font-bold transition-all border-b-2 ${
              activeTab === 'arena'
                ? 'bg-slate-900 text-amber-300 border-amber-400'
                : 'text-slate-400 hover:text-white border-transparent'
            }`}
          >
            <Flag className="w-3.5 h-3.5" />
            <span>Challenges Arena ({challenges.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('scoreboard')}
            className={`flex items-center gap-2 px-4 py-2 rounded-t-lg font-mono text-xs font-bold transition-all border-b-2 ${
              activeTab === 'scoreboard'
                ? 'bg-slate-900 text-cyan-300 border-cyan-400'
                : 'text-slate-400 hover:text-white border-transparent'
            }`}
          >
            <Trophy className="w-3.5 h-3.5" />
            <span>Live Scoreboard & First Bloods</span>
          </button>
        </div>

        {/* Active Team Identity Badge */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">Team:</span>
          <input
            type="text"
            value={teamName}
            onChange={(e) => setTeamName(e.target.value)}
            className="px-2 py-1 rounded bg-slate-900 border border-slate-700 text-slate-200 text-xs font-mono w-40 focus:border-amber-400 outline-none"
            placeholder="Team Name"
          />
        </div>
      </div>

      {/* Ephemeral Sandboxes Status Banner */}
      {sandboxes.length > 0 && (
        <div className="p-4 rounded-xl border border-cyan-500/30 bg-cyan-950/20 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-300 font-bold">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              <span>Active Ephemeral Sandboxes ({sandboxes.length}/3)</span>
            </div>
            <button
              onClick={handleReapSandboxes}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-cyan-800 text-[11px] font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
              title="Clean up all expired pods from the cluster"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reap Expired</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {sandboxes.map((sbx) => (
              <div
                key={sbx.id}
                className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white truncate max-w-[140px]">{sbx.challengeName || sbx.challengeId}</span>
                  <span className="text-[10px] text-amber-400">TTL: {sbx.remainingMinutes ?? 30}m</span>
                </div>
                <div className="text-[11px] text-slate-400 truncate">
                  <code>{sbx.connectionUrl || sbx.host}</code>
                </div>
                <div className="flex items-center gap-2 pt-1 border-t border-slate-800">
                  <button
                    onClick={() => handleExtendSandbox(sbx.id)}
                    className="flex-1 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] font-mono text-center transition-colors"
                  >
                    +15m TTL
                  </button>
                  <button
                    onClick={() => handleTerminateSandbox(sbx.id)}
                    className="flex-1 py-1 rounded bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/60 text-[10px] font-mono text-center transition-colors"
                  >
                    Terminate
                  </button>
                  <a
                    href={sbx.connectionUrl?.startsWith('http') ? sbx.connectionUrl : '#'}
                    target="_blank"
                    rel="noreferrer"
                    className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 1: CHALLENGES ARENA */}
      {activeTab === 'arena' && (
        <div className="space-y-6">
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

          {/* Challenges Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredChals.map((chal) => {
              const activeSbx = sandboxes.find((s) => s.challengeId === chal.id);
              const isSolved = chal.solved;
              const feedback = submitFeedback[chal.id];

              return (
                <div
                  key={chal.id}
                  className={`p-5 rounded-xl border flex flex-col justify-between space-y-4 transition-all group ${
                    isSolved
                      ? 'border-emerald-500/40 bg-emerald-950/10'
                      : 'border-slate-800 bg-slate-950/70 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          chal.difficulty === 'Easy' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                          chal.difficulty === 'Medium' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          'bg-rose-950 text-rose-300 border border-rose-800'
                        }`}>
                          {chal.difficulty}
                        </span>
                        {isSolved && (
                          <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/50 text-emerald-300 font-bold">
                            <CheckCircle2 className="w-3 h-3" />
                            SOLVED
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-xs font-mono">
                        <span className="text-amber-400 font-bold">{chal.currentPoints || 500} pts</span>
                        <span className="text-slate-500 text-[10px]">({chal.solvesCount || 0} solves)</span>
                      </div>
                    </div>

                    <h3 className="text-base font-bold text-white group-hover:text-amber-400 transition-colors flex items-center justify-between">
                      <span>{chal.name}</span>
                      {chal.firstBlood && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 border border-rose-800 text-rose-300 flex items-center gap-1" title={`First Blood: ${chal.firstBlood}`}>
                          🩸 {chal.firstBlood}
                        </span>
                      )}
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

                    {/* Inline Flag Submission Bar */}
                    <div className="space-y-1 pt-1">
                      <div className="flex items-center gap-1.5">
                        <input
                          type="text"
                          value={flagInputs[chal.id] || ''}
                          onChange={(e) => setFlagInputs({ ...flagInputs, [chal.id]: e.target.value })}
                          onKeyDown={(e) => e.key === 'Enter' && handleSubmitFlag(chal.id)}
                          placeholder="VIGILANTE{...}"
                          disabled={isSolved || submitting[chal.id]}
                          className="flex-1 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:border-amber-400 outline-none disabled:opacity-50"
                        />
                        <button
                          onClick={() => handleSubmitFlag(chal.id)}
                          disabled={isSolved || submitting[chal.id] || !flagInputs[chal.id]}
                          className="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 disabled:bg-slate-800 text-slate-950 disabled:text-slate-500 font-bold text-xs font-mono transition-colors flex items-center gap-1"
                        >
                          <Send className="w-3 h-3" />
                          <span>Submit</span>
                        </button>
                      </div>

                      {/* Submission Feedback Message */}
                      {feedback && (
                        <div className={`p-2 rounded text-[11px] font-mono ${
                          feedback.success
                            ? 'bg-emerald-950/80 border border-emerald-800 text-emerald-300'
                            : 'bg-rose-950/80 border border-rose-800 text-rose-300'
                        }`}>
                          {feedback.message}
                        </div>
                      )}
                    </div>

                    {/* Helper Modals (Mentor & Crash Triage) */}
                    <div className="flex items-center gap-2 pt-1">
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
                          setCrashModalOpen(true);
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
        </div>
      )}

      {/* TAB 2: LIVE SCOREBOARD & TICKER */}
      {activeTab === 'scoreboard' && (
        <div className="space-y-6">
          {scoreboardLoading ? (
            <div className="p-8 text-center text-xs font-mono text-slate-400">
              Loading tournament leaderboard & curves...
            </div>
          ) : scoreboardData ? (
            <div className="space-y-6">
              {/* Dynamic Score Progression Curves SVG */}
              {scoreboardData.svgChart && (
                <div className="p-4 rounded-xl border border-slate-800 bg-slate-950 space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span className="font-bold text-white flex items-center gap-2">
                      <Flame className="w-4 h-4 text-amber-400" />
                      Dynamic Score Progression Curves
                    </span>
                    <span>Elapsed: {scoreboardData.tournament?.state || 'ACTIVE'}</span>
                  </div>
                  <div
                    className="overflow-x-auto flex justify-center py-2"
                    dangerouslySetInnerHTML={{ __html: scoreboardData.svgChart }}
                  />
                </div>
              )}

              {/* Leaderboard Table & Recent Solves Split */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Leaderboard Table (2 Cols) */}
                <div className="lg:col-span-2 p-5 rounded-xl border border-slate-800 bg-slate-950/70 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="font-bold text-white text-sm font-mono flex items-center gap-2">
                      <Trophy className="w-4 h-4 text-amber-400" />
                      Tournament Leaderboard
                    </h3>
                    <span className="text-xs font-mono text-slate-400">
                      Total Teams: {scoreboardData.leaderboard?.length || 0}
                    </span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 text-left">
                          <th className="py-2 px-3">Rank</th>
                          <th className="py-2 px-3">Team</th>
                          <th className="py-2 px-3 text-right">Jeopardy</th>
                          <th className="py-2 px-3 text-right">KotH</th>
                          <th className="py-2 px-3 text-right">Solves</th>
                          <th className="py-2 px-3 text-right text-amber-300">Total Score</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scoreboardData.leaderboard?.map((t: any) => (
                          <tr key={t.id} className="border-b border-slate-800/50 hover:bg-slate-900/50">
                            <td className="py-2.5 px-3 font-bold">
                              {t.rank === 1 ? '🥇 1' : t.rank === 2 ? '🥈 2' : t.rank === 3 ? '🥉 3' : t.rank}
                            </td>
                            <td className="py-2.5 px-3 font-semibold text-white">{t.name}</td>
                            <td className="py-2.5 px-3 text-right text-slate-300">{t.jeopardyScore || 0}</td>
                            <td className="py-2.5 px-3 text-right text-purple-300">{t.kothScore || 0}</td>
                            <td className="py-2.5 px-3 text-right text-cyan-300">{t.solvesCount || 0}</td>
                            <td className="py-2.5 px-3 text-right font-bold text-amber-400">{t.totalScore}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* First Blood & Solve Ticker (1 Col) */}
                <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/70 space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <h3 className="font-bold text-white text-sm font-mono flex items-center gap-2">
                      <Zap className="w-4 h-4 text-cyan-400" />
                      Live Solves & First Bloods
                    </h3>
                  </div>

                  <div className="space-y-2.5 max-h-[400px] overflow-y-auto pr-1">
                    {scoreboardData.recentSolves?.length === 0 ? (
                      <p className="text-xs text-slate-500 font-mono">No solves registered yet. First blood awaits!</p>
                    ) : (
                      scoreboardData.recentSolves?.map((solve: any, idx: number) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1 text-xs font-mono"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-white">{solve.teamName}</span>
                            <span className="text-amber-400 font-semibold">+{solve.points} pts</span>
                          </div>
                          <div className="flex items-center justify-between text-[11px] text-slate-400">
                            <span>{solve.challengeName || solve.challengeId}</span>
                            {solve.bloodBadge && (
                              <span className="text-rose-400 font-bold">{solve.bloodBadge} First Blood</span>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-xs font-mono text-slate-500">
              Scoreboard unavailable. Check tournament status.
            </div>
          )}
        </div>
      )}

      {/* Crash Triage Modal */}
      {crashModalOpen && selectedChallenge && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-purple-400" />
                <h3 className="font-bold text-white text-base font-mono">
                  Crash & Register State Triage: {selectedChallenge.name}
                </h3>
              </div>
              <button
                onClick={() => setCrashModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400">Sample Presets:</label>
              <div className="flex flex-wrap gap-2 text-xs font-mono">
                <button
                  onClick={() => setCrashLog("Program received signal SIGSEGV, Segmentation fault.\n0x4141414141414141 in ?? ()\n(gdb) info registers\nrax            0x0                 0\nrbx            0x0                 0\nrcx            0x7fffffffe000      140737488347136\nrdx            0x100               256\nrsi            0x7fffffffe100      140737488347392\nrdi            0x1                 1\nrbp            0x4242424242424242  0x4242424242424242\nrsp            0x7fffffffe200      0x7fffffffe200\nrip            0x4141414141414141  0x4141414141414141")}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-purple-500 text-purple-300"
                >
                  SIGSEGV: RIP Overwrite (0x4141...)
                </button>
                <button
                  onClick={() => setCrashLog("dmesg: a.out[1234]: segfault at 7ffff7a01234 ip 00007ffff7a01234 sp 00007fffffffe340 error 14 in libc.so.6")}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-purple-500 text-purple-300"
                >
                  Kernel Segfault (dmesg)
                </button>
                <button
                  onClick={() => setCrashLog("Received: 0x7fffffffe310.0x100.0x7ffff7fa3000.0x41414141")}
                  className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-purple-500 text-purple-300"
                >
                  Format String Leak
                </button>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-mono text-slate-400">Paste gdb, pwntools, or kernel dmesg crash register dump:</label>
              <textarea
                value={crashLog}
                onChange={(e) => setCrashLog(e.target.value)}
                placeholder="Paste register state or backtrace here..."
                className="w-full h-32 bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 outline-none focus:border-purple-500"
              />
            </div>

            <button
              onClick={handleAnalyzeCrash}
              disabled={crashLoading || !crashLog}
              className="w-full py-2.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs font-mono transition-colors disabled:opacity-50"
            >
              {crashLoading ? 'Triaging Faulting Instruction...' : 'Analyze Crash & Register State'}
            </button>

            {crashDiagnosis && (
              <div className="p-4 rounded-xl bg-slate-900/90 border border-purple-800/60 space-y-3 text-xs font-mono">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="font-bold text-purple-300">Exploitability Rating:</span>
                  <span className={`px-2 py-0.5 rounded font-bold ${
                    crashDiagnosis.exploitability === 'EXPLOITABLE' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    crashDiagnosis.exploitability === 'PROBABLY_EXPLOITABLE' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {crashDiagnosis.exploitability || 'UNKNOWN'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div><strong className="text-slate-400">Signal:</strong> <span className="text-white">{crashDiagnosis.signal || 'SIGSEGV'}</span></div>
                  <div><strong className="text-slate-400">Faulting Address:</strong> <span className="text-amber-400">{crashDiagnosis.faultAddress || 'N/A'}</span></div>
                </div>

                {crashDiagnosis.analysis && (
                  <div className="space-y-1">
                    <strong className="text-slate-400 text-[11px]">Diagnosis & Offset Findings:</strong>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300 whitespace-pre-wrap text-[11px] leading-relaxed">
                      {crashDiagnosis.analysis}
                    </div>
                  </div>
                )}

                {crashDiagnosis.suggestedSteps && (
                  <div className="space-y-1">
                    <strong className="text-slate-400 text-[11px]">Recommended Next Exploitation Steps:</strong>
                    <ul className="list-disc pl-4 space-y-0.5 text-slate-300 text-[11px]">
                      {crashDiagnosis.suggestedSteps.map((step: string, i: number) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

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
