'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Activity,
  Server,
  FileCode,
  Radar,
  Radio,
  Cpu,
  ShieldAlert,
  Flame,
  Swords,
  Clock,
  Layers,
  Flag,
  Share2,
  FileSearch,
  GitFork,
  Cloud,
  FileCheck2,
  Terminal,
  Search,
  Command,
  Key,
  LogOut,
  LogIn,
  ShieldCheck,
  BookOpen
} from 'lucide-react';
import { CommandPalette } from './CommandPalette';
import { useAbilityContext } from '@/lib/ability';

const NAV_SECTIONS = [
  {
    title: 'CTF Cyber Range',
    items: [
      { href: '/event', label: 'Player Field Manual', icon: BookOpen, badge: 'Guide' },
      { href: '/ctf', label: 'kCTF Arena', icon: Flag, pulse: true },
    ]
  },
  {
    title: 'Phase 1: Readiness',
    items: [
      { href: '/', label: 'Ops Hub', icon: Activity },
      { href: '/instances', label: 'Cluster Instances', icon: Server },
      { href: '/values', label: 'Helm Values', icon: FileCode },
      { href: '/settings/access', label: 'Access Control', icon: Key },
    ]
  },

  {
    title: 'Phase 2: Detection & Analysis',
    items: [
      { href: '/nastymap', label: 'NastyMap Recon', icon: Radar, badge: '2D/3D' },
      { href: '/battlestation', label: 'BattleStation SOC', icon: Radio, pulse: true },
      { href: '/pods', label: 'Live Pods Monitor', icon: Server },
      { href: '/openvas', label: 'OpenVAS Scanner', icon: ShieldAlert },
      { href: '/oobscan', label: 'OOBscan BMC', icon: Cpu },
      { href: '/vuln', label: 'Vulnerability Brain', icon: ShieldAlert },
      { href: '/posture', label: 'KSPM & MITRE', icon: ShieldAlert },
      { href: '/forensics', label: 'PCAP Forensics', icon: FileSearch },
      { href: '/lineage', label: 'eBPF Process Tree', icon: GitFork },
      { href: '/cloudsec', label: 'CloudSec & CSPM', icon: Cloud },
      { href: '/timeline', label: 'Attack Timeline', icon: Clock },
      { href: '/sniffer', label: 'Packet Sniffer', icon: Radio },
      { href: '/graph', label: 'Attack Graph', icon: Share2 },
      { href: '/analyst', label: 'Socratic Analyst', icon: Cpu },
    ]
  },
  {
    title: 'Phase 3: Containment & Range',
    items: [
      { href: '/audit', label: 'Shift-Left Audit', icon: FileCheck2 },
      { href: '/deception', label: 'Canary Deception', icon: ShieldAlert },
      { href: '/purpleteam', label: 'Purple Team Arena', icon: Swords },
      { href: '/threatsim', label: 'Threat Sim Engine', icon: Flame },
      { href: '/ctf', label: 'kCTF Cyber Range', icon: Flag },
      { href: '/modules', label: 'Cluster Modules', icon: Layers },
    ]
  }
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [isPaletteOpen, setIsPaletteOpen] = useState(false);
  const { status, principal, signOut, openSignInPrompt } = useAbilityContext();

  return (
    <>
      <CommandPalette isOpen={isPaletteOpen} onClose={() => setIsPaletteOpen(false)} />

      {/* Top Navbar */}
      <header className="h-14 border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md px-4 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold font-mono">
            ⚡
          </div>
          <div>
            <span className="font-bold tracking-wider text-slate-100 flex items-center gap-2">
              VIGILANTE <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">Web Ops</span>
            </span>
          </div>
        </div>

        {/* Middle: Command Palette Quick Search Button */}
        <button
          onClick={() => setIsPaletteOpen(true)}
          className="hidden sm:flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs text-slate-400 font-mono transition-colors"
        >
          <Search className="w-3.5 h-3.5 text-cyan-400" />
          <span>Quick command search...</span>
          <kbd className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-400">
            Ctrl+K
          </kbd>
        </button>

        <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
          <div className="hidden xl:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Cluster: <strong className="text-slate-200">vigilante-dev</strong></span>
          </div>
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
            <span>Domain: <strong className="text-cyan-400">vigilante.local</strong></span>
          </div>

          {/* Auth Status & Controls */}
          {status === 'ready' && principal ? (
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300">
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>
                <strong>{principal.name}</strong>{' '}
                <span className="text-[10px] uppercase px-1 rounded bg-cyan-900/60 text-cyan-200">
                  {principal.role}
                </span>
              </span>
              <button
                onClick={() => void signOut()}
                title="Sign out"
                className="text-slate-400 hover:text-rose-400 transition-colors ml-1 p-0.5"
              >
                <LogOut className="w-3 h-3" />
              </button>
            </div>
          ) : status === 'local-board' ? (
            <Link
              href="/settings/access"
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-950/60 border border-amber-800/60 text-amber-300 hover:bg-amber-900/40 transition-colors"
            >
              <Key className="w-3.5 h-3.5 text-amber-400" />
              <span>Local Board</span>
              <span className="text-[9px] uppercase px-1 rounded bg-amber-900/80 text-amber-200">Setup</span>
            </Link>
          ) : (
            <button
              onClick={openSignInPrompt}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-colors"
            >
              <LogIn className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </button>
          )}

          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900/60 border border-slate-800 text-slate-400">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>CLI: <code>pnpm cli</code></span>
          </div>
        </div>
      </header>


      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-64 border-r border-slate-800/80 bg-slate-950/40 p-3 flex flex-col justify-between shrink-0 hidden md:flex overflow-y-auto">
          <div className="space-y-4">
            {NAV_SECTIONS.map((sec, secIdx) => (
              <div key={secIdx} className="space-y-1">
                <div className="px-2.5 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-500">
                  {sec.title}
                </div>
                {sec.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = pathname === item.href;

                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all group ${
                        isActive
                          ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-800/80 shadow-sm'
                          : 'text-slate-400 hover:text-white hover:bg-slate-900/80 border border-transparent hover:border-slate-800'
                      }`}
                    >
                      <div className="flex items-center gap-2.5 truncate">
                        <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-cyan-400'}`} />
                        <span className="truncate">{item.label}</span>
                      </div>
                      {item.badge && (
                        <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/30 shrink-0">
                          {item.badge}
                        </span>
                      )}
                      {item.pulse && (
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping shrink-0"></span>
                      )}
                    </Link>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Monorepo Info Footer */}
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[10px] font-mono text-slate-400 space-y-1 mt-4">
            <div className="flex items-center justify-between text-slate-300 font-semibold">
              <span>Engine</span>
              <span className="text-cyan-400">vigilante_lib</span>
            </div>
            <p className="text-[9px] text-slate-500 leading-tight">
              Shared headless cybersecurity core across terminal CLI & Web Ops.
            </p>
          </div>
        </aside>

        {/* Main View Area */}
        <main className="flex-1 overflow-y-auto bg-gradient-to-b from-[#070a13] to-[#0a0f1d] p-6">
          {children}
        </main>
      </div>
    </>
  );
}
