import type { Metadata } from 'next';
import './globals.css';
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
  Compass
} from 'lucide-react';

export const metadata: Metadata = {
  title: 'Vigilante | Autonomous Security Operations Platform',
  description: 'Cyber battle station, dynamic NastyMap network visualizer, kCTF arena, and eBPF security telemetry.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const navItems = [
    { href: '/', label: 'Ops Hub', icon: Activity },
    { href: '/nastymap', label: 'NastyMap Recon', icon: Radar, badge: 'Flagship' },
    { href: '/battlestation', label: 'BattleStation SOC', icon: Radio, pulse: true },
    { href: '/ctf', label: 'kCTF Arena', icon: Flag },
    { href: '/graph', label: 'Attack Graph', icon: Share2 },
    { href: '/modules', label: 'Cluster Modules', icon: Layers },
    { href: '/analyst', label: 'Socratic Analyst', icon: Cpu },
    { href: '/posture', label: 'KSPM & MITRE', icon: ShieldAlert },
  ];

  return (
    <html lang="en" className="dark">
      <body className="bg-[#070a13] text-slate-100 min-h-screen flex flex-col font-sans">
        {/* Top Navbar */}
        <header className="h-14 border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md px-4 flex items-center justify-between sticky top-0 z-50">
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

          <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>Cluster: <strong className="text-slate-200">vigilante-dev</strong></span>
            </div>
            <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
              <span>Domain: <strong className="text-cyan-400">vigilante.local</strong></span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900/60 border border-slate-800 text-slate-400">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>CLI: <code>pnpm cli</code></span>
            </div>
          </div>
        </header>

        <div className="flex flex-1 overflow-hidden">
          {/* Sidebar */}
          <aside className="w-64 border-r border-slate-800/80 bg-slate-950/40 p-4 flex flex-col justify-between shrink-0 hidden md:flex">
            <div className="space-y-1.5">
              <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500">
                Core Panes
              </div>
              {navItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className="flex items-center justify-between px-3 py-2 rounded-md text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-900/80 border border-transparent hover:border-slate-800 transition-all group"
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className="w-4 h-4 text-slate-400 group-hover:text-cyan-400 transition-colors" />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/30">
                        {item.badge}
                      </span>
                    )}
                    {item.pulse && (
                      <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
                    )}
                  </Link>
                );
              })}
            </div>

            {/* Monorepo Info Footer */}
            <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
              <div className="flex items-center justify-between text-slate-300 font-semibold">
                <span>Architecture</span>
                <span className="text-cyan-400">Monorepo</span>
              </div>
              <p className="text-[10px] text-slate-500">
                Frontends share <code>packages/vigilante_lib</code> headless core engine.
              </p>
            </div>
          </aside>

          {/* Main View Area */}
          <main className="flex-1 overflow-y-auto bg-gradient-to-b from-[#070a13] to-[#0a0f1d] p-6">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
