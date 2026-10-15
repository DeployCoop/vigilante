'use client';

import React, { useState, useEffect } from 'react';
import {
  Swords,
  Play,
  RefreshCw,
  Trophy,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Target,
  Zap,
  Layers
} from 'lucide-react';

export default function PurpleTeamPage() {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('lateral-smb-exfil');
  const [loading, setLoading] = useState<boolean>(true);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [lastSimulation, setLastSimulation] = useState<any>(null);
  const [scorecard, setScorecard] = useState<any>(null);

  const fetchScenarios = () => {
    setLoading(true);
    fetch('/api/purpleteam')
      .then((res) => res.json())
      .then((d) => {
        if (d.success) {
          setScenarios(d.scenarios || []);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchScenarios();
  }, []);

  const handleStartSimulation = async () => {
    setSimulating(true);
    try {
      const res = await fetch('/api/purpleteam', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioKey: selectedScenario })
      });
      const data = await res.json();
      if (data.success) {
        setLastSimulation(data.simulation);
        setScorecard(data.scorecard);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSimulating(false);
    }
  };

  const getGradeColor = (grade: string) => {
    if (grade?.startsWith('A')) return 'text-emerald-400 bg-emerald-950/80 border-emerald-800';
    if (grade?.startsWith('B')) return 'text-cyan-400 bg-cyan-950/80 border-cyan-800';
    if (grade?.startsWith('C')) return 'text-yellow-400 bg-yellow-950/80 border-yellow-800';
    return 'text-rose-400 bg-rose-950/80 border-rose-800';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
            <Swords className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Autonomous Purple Team Arena (Wargames)
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 border border-red-800 text-red-300">
                Red vs. Blue ReAct
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Multi-agent adversarial simulation pitting automated Red Adversary against Blue ReAct SOC & active SOAR containment.
            </p>
          </div>
        </div>

        <button
          onClick={fetchScenarios}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 border border-slate-800"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Main Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        {/* Left: Scenarios Selector */}
        <div className="space-y-4 lg:col-span-1">
          <div className="p-5 rounded-xl border border-slate-800 bg-slate-950/60 space-y-4">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Target className="w-4 h-4 text-rose-400" />
              <span>Adversary Wargame Scenarios</span>
            </h2>

            <div className="space-y-2">
              {scenarios.map((s) => (
                <label
                  key={s.id}
                  onClick={() => setSelectedScenario(s.id)}
                  className={`block p-3.5 rounded-lg border cursor-pointer transition-all ${
                    selectedScenario === s.id
                      ? 'bg-rose-950/40 border-rose-500/50 text-white'
                      : 'bg-slate-900/40 border-slate-800 text-slate-400 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between font-bold">
                    <span>{s.name}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 pt-1">
                    Adversary: <strong className="text-rose-400">{s.adversaryGroup}</strong>
                  </div>
                  <div className="text-[10px] text-slate-500 pt-0.5">
                    Target: {s.targetWorkload} ({s.targetNamespace}) | Steps: {s.stepsCount}
                  </div>
                </label>
              ))}
            </div>

            <button
              onClick={handleStartSimulation}
              disabled={simulating}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:bg-rose-900 text-white font-bold transition-colors shadow-lg shadow-rose-900/20"
            >
              {simulating ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Executing Adversary Wargame...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Start Autonomous Purple Wargame</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Right: Simulation Output & Defense Scorecard */}
        <div className="lg:col-span-2 space-y-4">
          {scorecard ? (
            <div className="space-y-4">
              {/* Scorecard Hero Banner */}
              <div className="p-6 rounded-xl border border-slate-800 bg-slate-950/80 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                      <Trophy className="w-6 h-6 text-amber-400" />
                    </div>
                    <div>
                      <h3 className="text-base font-bold text-white">Defense Verdict & ATT&CK Scorecard</h3>
                      <p className="text-slate-400 text-xs">
                        Adversary: {lastSimulation?.scenarioName || 'Wargame'}
                      </p>
                    </div>
                  </div>

                  <span className={`text-xl font-extrabold px-3 py-1 rounded-lg border ${getGradeColor(scorecard.grade)}`}>
                    Grade [{scorecard.grade}]
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 uppercase">Defense Score</div>
                    <div className="text-lg font-bold text-white pt-0.5">{scorecard.score} / 100</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 uppercase">Verdict</div>
                    <div className={`text-lg font-bold pt-0.5 ${scorecard.contained ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {scorecard.contained ? 'CONTAINED' : 'EXFILTRATED'}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 uppercase">Mean Time To Detect</div>
                    <div className="text-lg font-bold text-cyan-400 pt-0.5">{scorecard.mttdSec}s</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-center">
                    <div className="text-[10px] text-slate-500 uppercase">Containment Step</div>
                    <div className="text-lg font-bold text-amber-400 pt-0.5">Step {scorecard.containmentStep}</div>
                  </div>
                </div>

                {/* Recommendations */}
                <div className="pt-3 border-t border-slate-800/80 space-y-1.5">
                  <div className="text-slate-400 font-bold uppercase text-[10px]">Hardening Recommendations:</div>
                  {(scorecard.recommendations || []).map((rec: string, i: number) => (
                    <div key={i} className="text-slate-300 text-[11px] flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0"></span>
                      <span>{rec}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Rounds Trace */}
              {lastSimulation?.rounds && (
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
                  <div className="p-3 bg-slate-900/80 border-b border-slate-800 text-slate-400 font-bold uppercase text-[11px]">
                    Kill Chain Execution Steps
                  </div>
                  <div className="divide-y divide-slate-800/60">
                    {lastSimulation.rounds.map((r: any, idx: number) => (
                      <div key={idx} className="p-3.5 flex items-start justify-between gap-4">
                        <div className="space-y-1">
                          <div className="font-bold text-white flex items-center gap-2">
                            <span className="text-rose-400">Step {idx + 1}: {r.action}</span>
                          </div>
                          <div className="text-[11px] text-slate-400">{r.techniqueName} ({r.techniqueId})</div>
                          <div className="text-[10px] text-slate-500">
                            Detected by: {r.detectedBy?.join(', ') || 'Sensor'}
                          </div>
                        </div>
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded border ${
                            r.blocked
                              ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                              : 'bg-rose-950 text-rose-400 border-rose-800'
                          }`}
                        >
                          {r.blocked ? 'BLOCKED' : 'EXECUTED'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-96 rounded-xl border border-slate-800 bg-slate-950/40 flex flex-col items-center justify-center text-center p-6 space-y-3 font-mono text-xs text-slate-500">
              <Swords className="w-8 h-8 text-slate-600" />
              <p>No Purple Team simulation executed yet.</p>
              <p className="text-[11px] text-slate-600">
                Select an APT adversary scenario on the left and click &quot;Start Autonomous Purple Wargame&quot; to measure detection dwell time.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
