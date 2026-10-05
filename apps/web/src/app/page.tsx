'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  Radar,
  Radio,
  Flag,
  Share2,
  Layers,
  Cpu,
  ShieldAlert,
  Terminal,
  Activity,
  Server,
  Zap,
  CheckCircle2,
  AlertTriangle,
  ArrowRight
} from 'lucide-react';

export default function DashboardPage() {
  const [status, setStatus] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/status')
      .then((res) => res.json())
      .then((data) => {
        setStatus(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const quickPanes = [
    {
      title: 'NastyMap Recon Suite',
      desc: 'Interactive 2D force-directed network topology, GeoIP world mapping, and scan diffing.',
      href: '/nastymap',
      icon: Radar,
      color: 'from-cyan-500/20 to-blue-500/10 border-cyan-500/30 text-cyan-400',
      badge: 'Flagship Visualization'
    },
    {
      title: 'BattleStation Live SOC',
      desc: 'Dual-pane real-time telemetry stream combining eBPF Falco runtime events and Zeek/Suricata IDS alerts.',
      href: '/battlestation',
      icon: Radio,
      color: 'from-rose-500/20 to-purple-500/10 border-rose-500/30 text-rose-400',
      badge: 'Live Streaming'
    },
    {
      title: 'kCTF Cyber Range & Arena',
      desc: 'Multi-mode tournament orchestrator, ephemeral pod spawner, live scoreboard curves, and Socratic hints.',
      href: '/ctf',
      icon: Flag,
      color: 'from-amber-500/20 to-yellow-500/10 border-amber-500/30 text-amber-400',
      badge: 'Range Platform'
    },
    {
      title: 'Composite Attack Graph',
      desc: 'Multi-hop kill chain topology from external adversary to cluster-admin with blast-radius simulation.',
      href: '/graph',
      icon: Share2,
      color: 'from-purple-500/20 to-indigo-500/10 border-purple-500/30 text-purple-400',
      badge: 'Impact Analysis'
    }
  ];

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-cyan-950/30 p-8">
        <div className="relative z-10 max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-400">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
            Unified Monorepo Architecture: packages/vigilante_lib + apps/web + apps/ink
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
            Vigilante Autonomous Security Operations Platform
          </h1>
          <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
            Full-stack security intelligence for Kubernetes clusters, offensive & defensive cyber ranges, and automated incident triage. Both this Next.js site and the terminal CLI share the identical high-performance <code>vigilante_lib</code> core engine.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Link
              href="/nastymap"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-colors shadow-lg shadow-cyan-500/20"
            >
              <Radar className="w-4 h-4" />
              Launch NastyMap Visualizer
            </Link>
            <Link
              href="/ctf"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium text-sm border border-slate-700 transition-colors"
            >
              <Flag className="w-4 h-4 text-amber-400" />
              Open kCTF Range
            </Link>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono pb-2">
            <span>CLUSTER HEALTH</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white flex items-center gap-2">
            <span>ONLINE</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="text-xs text-slate-500 font-mono pt-1">Context: k3d-vigilante-dev</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono pb-2">
            <span>SECURITY MODULES</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {loading ? '...' : `${status?.modulesCount || 12} Registered`}
          </div>
          <div className="text-xs text-slate-500 font-mono pt-1">Suricata, Zeek, OpenVAS, kCTF</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono pb-2">
            <span>ACTIVE NAMESPACES</span>
            <Server className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {loading ? '...' : `${status?.namespaces?.length || 5} Active`}
          </div>
          <div className="text-xs text-slate-500 font-mono pt-1">kctf, threat-lab, monitoring</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono pb-2">
            <span>FRONTEND RUNNERS</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white flex items-center gap-2">
            <span>Next.js + Ink</span>
          </div>
          <div className="text-xs text-slate-500 font-mono pt-1">Terminal + Browser Parity</div>
        </div>
      </div>

      {/* Flagship Feature Grid */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-white flex items-center gap-2">
          <span>Explore Platform Workspaces</span>
          <span className="text-xs font-mono text-slate-500 font-normal">| Feature Parity with Terminal CLI</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {quickPanes.map((pane) => {
            const Icon = pane.icon;
            return (
              <Link
                key={pane.href}
                href={pane.href}
                className={`p-6 rounded-xl border bg-gradient-to-br transition-all hover:scale-[1.01] hover:border-cyan-500/50 group ${pane.color}`}
              >
                <div className="flex items-start justify-between">
                  <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80">
                    <Icon className="w-6 h-6" />
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-950/90 border border-slate-800 text-slate-300">
                    {pane.badge}
                  </span>
                </div>
                <div className="pt-4 space-y-1">
                  <h3 className="text-base font-bold text-white group-hover:text-cyan-400 transition-colors flex items-center gap-1.5">
                    <span>{pane.title}</span>
                    <ArrowRight className="w-4 h-4 opacity-0 group-hover:opacity-100 group-hover:translate-x-1 transition-all" />
                  </h3>
                  <p className="text-sm text-slate-400 leading-relaxed">
                    {pane.desc}
                  </p>
                </div>
              </Link>
            );
          })}
        </div>
      </div>

      {/* Terminal CLI Parity Tip */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 font-mono text-xs">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold">
            <Terminal className="w-4 h-4" />
            <span>Dual Operations Interface: CLI Terminal Tool</span>
          </div>
          <p className="text-slate-400 text-[11px]">
            Prefer running in a pure terminal window? Launch the companion Ink application from anywhere in the monorepo:
          </p>
        </div>
        <div className="px-3 py-2 rounded bg-slate-900 border border-slate-800 text-cyan-300 select-all shrink-0">
          pnpm cli
        </div>
      </div>
    </div>
  );
}
