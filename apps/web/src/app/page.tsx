'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
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
  Zap,
  CheckCircle2,
  ArrowRight
} from 'lucide-react';

const OPERATIONS_SECTIONS = [
  {
    title: '🛠️ NIST Phase 1: Preparation & Readiness',
    tools: [
      {
        title: 'Cluster Instances Manager',
        desc: 'Manage isolated multi-cluster k3d instances, directories, and certs.',
        href: '/instances',
        icon: Server,
        color: 'border-cyan-500/30 text-cyan-400 from-cyan-950/20 to-slate-900/60',
        badge: 'Multi-Cluster',
        key: '3'
      },
      {
        title: 'Helm Values Editor & Overrides',
        desc: 'Inspect chart parameters, default templates, and customized XDG values.yaml.',
        href: '/values',
        icon: FileCode,
        color: 'border-teal-500/30 text-teal-400 from-teal-950/20 to-slate-900/60',
        badge: 'Helm Engine',
        key: '4'
      }
    ]
  },
  {
    title: '🔍 NIST Phase 2: Detection & Analysis',
    tools: [
      {
        title: 'NastyMap Recon Suite',
        desc: 'Interactive 2D force-directed network topology, GeoIP mapping, and scan diffing.',
        href: '/nastymap',
        icon: Radar,
        color: 'border-cyan-500/30 text-cyan-400 from-cyan-950/30 to-blue-950/20',
        badge: 'Flagship Recon',
        key: '5'
      },
      {
        title: 'BattleStation Live SOC',
        desc: 'Dual-pane real-time telemetry stream combining eBPF Falco events and Zeek/Suricata IDS.',
        href: '/battlestation',
        icon: Radio,
        color: 'border-rose-500/30 text-rose-400 from-rose-950/30 to-purple-950/20',
        badge: 'Live Streaming',
        key: 'l'
      },
      {
        title: 'Kubernetes Live Pods Monitor',
        desc: 'Real-time kubectl -A -o wide table with container logs, describe, and status.',
        href: '/pods',
        icon: Server,
        color: 'border-emerald-500/30 text-emerald-400 from-emerald-950/20 to-slate-900/60',
        badge: 'Workloads',
        key: '8'
      },
      {
        title: 'OpenVAS Vulnerability Scanner',
        desc: 'CVE scans, port audits, compliance checks, and Greenbone Management Protocol reports.',
        href: '/openvas',
        icon: ShieldAlert,
        color: 'border-rose-500/30 text-rose-400 from-rose-950/20 to-slate-900/60',
        badge: '85,000+ NVTs',
        key: 'o'
      },
      {
        title: 'OOBscan BMC & Hardware Audit',
        desc: 'Audit IPMI, Redfish, iLO, iDRAC, Intel AMT, RAKP hashes, and BMC link-local.',
        href: '/oobscan',
        icon: Cpu,
        color: 'border-amber-500/30 text-amber-400 from-amber-950/20 to-slate-900/60',
        badge: 'BMC / IPMI',
        key: 'b'
      },
      {
        title: 'Vulnerability Center & Brain',
        desc: 'Unified host dossiers, normalized risk scores, PCAP replay, and BloodHound paths.',
        href: '/vuln',
        icon: ShieldAlert,
        color: 'border-pink-500/30 text-pink-400 from-pink-950/20 to-slate-900/60',
        badge: 'Host Dossiers',
        key: 'v'
      },
      {
        title: 'KSPM & CIS Benchmarks',
        desc: 'Continuous Pod Security Standards (PSS), CIS K8s Benchmarks, and ATT&CK heatmap.',
        href: '/posture',
        icon: ShieldAlert,
        color: 'border-emerald-500/30 text-emerald-400 from-emerald-950/20 to-slate-900/60',
        badge: 'Compliance',
        key: 'k'
      },
      {
        title: 'PCAP Forensics & Protocol Carving',
        desc: 'Carve files from packet flows, inspect decrypted TLS, and view TCP flow ladders.',
        href: '/forensics',
        icon: FileSearch,
        color: 'border-indigo-500/30 text-indigo-400 from-indigo-950/20 to-slate-900/60',
        badge: 'Forensics',
        key: 'z'
      },
      {
        title: 'eBPF Process Lineage Tree',
        desc: 'Container process hierarchy, shell breakout detection, LOLBins, and anomaly alerts.',
        href: '/lineage',
        icon: GitFork,
        color: 'border-emerald-500/30 text-emerald-400 from-emerald-950/20 to-slate-900/60',
        badge: 'Kernel eBPF',
        key: 'e'
      },
      {
        title: 'Multi-Cloud CSPM & Workload Identity',
        desc: 'Audit AWS IRSA roles, GCP Workload Identity, Azure Client IDs, and cloud storage.',
        href: '/cloudsec',
        icon: Cloud,
        color: 'border-sky-500/30 text-sky-400 from-sky-950/20 to-slate-900/60',
        badge: 'CSPM / CIEM',
        key: 'c'
      },
      {
        title: 'Attack Timeline & Causal DAG',
        desc: 'Traverse multi-stage attack chains, trace process lineage, and pinpoint dwell time.',
        href: '/timeline',
        icon: Clock,
        color: 'border-purple-500/30 text-purple-400 from-purple-950/20 to-slate-900/60',
        badge: 'Causal DAG',
        key: 't'
      },
      {
        title: 'Live Packet Sniffer & Dissector',
        desc: 'Ethernet/IP/TCP/UDP/DNS/TLS packet dissection, side-by-side hex dump, and PCAP export.',
        href: '/sniffer',
        icon: Radio,
        color: 'border-teal-500/30 text-teal-400 from-teal-950/20 to-slate-900/60',
        badge: 'Wireshark Web',
        key: 'u'
      },
      {
        title: 'Composite Attack Graph',
        desc: 'Multi-hop kill chain topology from external adversary to cluster-admin with blast radius.',
        href: '/graph',
        icon: Share2,
        color: 'border-purple-500/30 text-purple-400 from-purple-950/20 to-indigo-950/20',
        badge: 'Kill Chains',
        key: 'x'
      },
      {
        title: 'Socratic AI Security Analyst',
        desc: 'Local Ollama, Claude, or ChatGPT grounded in real-time MCP cluster context.',
        href: '/analyst',
        icon: Cpu,
        color: 'border-cyan-500/30 text-cyan-400 from-cyan-950/20 to-slate-900/60',
        badge: 'NIST Copilot',
        key: '7'
      }
    ]
  },
  {
    title: '⚡ NIST Phase 3: Containment, Eradication & Recovery',
    tools: [
      {
        title: 'Shift-Left CI/CD Security Audit',
        desc: 'Scan K8s manifests & Dockerfiles with SARIF v2.1.0 output and blocking pipeline gates.',
        href: '/audit',
        icon: FileCheck2,
        color: 'border-emerald-500/30 text-emerald-400 from-emerald-950/20 to-slate-900/60',
        badge: 'SARIF v2.1',
        key: 'g'
      },
      {
        title: 'Autonomous Deception Mesh',
        desc: 'Deploy decoy ServiceAccounts, canary secret tokens, and honeypot network services.',
        href: '/deception',
        icon: ShieldAlert,
        color: 'border-yellow-500/30 text-yellow-400 from-yellow-950/20 to-slate-900/60',
        badge: 'Canary Kube',
        key: 'y'
      },
      {
        title: 'Autonomous Purple Team Arena',
        desc: 'Multi-agent adversarial simulation: Red Adversary vs. Blue ReAct SOC & active SOAR.',
        href: '/purpleteam',
        icon: Swords,
        color: 'border-red-500/30 text-red-400 from-red-950/20 to-slate-900/60',
        badge: 'Wargames',
        key: 'w'
      },
      {
        title: 'Threat Simulation Engine',
        desc: 'Inject synthetic MITRE/NIST attack vectors and precursor telemetry into OpenSearch SIEM.',
        href: '/threatsim',
        icon: Flame,
        color: 'border-orange-500/30 text-orange-400 from-orange-950/20 to-slate-900/60',
        badge: 'Playbooks',
        key: '9'
      },
      {
        title: 'kCTF Cyber Range & Arena',
        desc: 'Multi-mode tournament orchestrator, ephemeral pod spawner, and live scoreboard curves.',
        href: '/ctf',
        icon: Flag,
        color: 'border-amber-500/30 text-amber-400 from-amber-950/20 to-yellow-950/20',
        badge: 'CTF Range',
        key: 'f'
      },
      {
        title: 'Security Modules & Stacks',
        desc: 'Deploy, configure, and teardown modular SIEM, SOC, and containment stacks per namespace.',
        href: '/modules',
        icon: Layers,
        color: 'border-cyan-500/30 text-cyan-400 from-cyan-950/20 to-slate-900/60',
        badge: '12 Stacks',
        key: '0'
      }
    ]
  }
];

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

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-cyan-950/30 p-8">
        <div className="relative z-10 max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-400">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
            Full Monorepo Parity: Next.js Web Ops ⟷ Ink Terminal CLI
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
            Vigilante Operations Hub & Workflow Dispatcher
          </h1>
          <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
            Autonomous cybersecurity operations platform for Kubernetes clusters. Seamlessly switch between the terminal interface (<code>pnpm cli</code>) and this web portal with full feature parity across all 24 security tools.
          </p>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Link
              href="/nastymap"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-colors shadow-lg shadow-cyan-500/20 font-mono"
            >
              <Radar className="w-4 h-4" />
              NastyMap Recon [5]
            </Link>
            <Link
              href="/battlestation"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium text-sm transition-colors font-mono"
            >
              <Radio className="w-4 h-4" />
              BattleStation SOC [l]
            </Link>
            <Link
              href="/pods"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium text-sm border border-slate-700 transition-colors font-mono"
            >
              <Server className="w-4 h-4 text-emerald-400" />
              Live Pods Monitor [8]
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
          <div className="text-2xl font-bold text-white flex items-center gap-2 font-mono">
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
          <div className="text-2xl font-bold text-white font-mono">
            {loading ? '...' : `${status?.modulesCount || 12} Registered`}
          </div>
          <div className="text-xs text-slate-500 font-mono pt-1">Suricata, Zeek, OpenVAS, Wazuh</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono pb-2">
            <span>TOTAL TOOLS & PANES</span>
            <Server className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">24 Core Tools</div>
          <div className="text-xs text-slate-500 font-mono pt-1">100% Terminal Parity</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono pb-2">
            <span>QUICK NAVIGATION</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white flex items-center gap-2 font-mono">
            <span>Ctrl + K</span>
          </div>
          <div className="text-xs text-slate-500 font-mono pt-1">Global Command Palette</div>
        </div>
      </div>

      {/* Categorized Tools Sections (NIST Framework) */}
      <div className="space-y-8">
        {OPERATIONS_SECTIONS.map((sec, idx) => (
          <div key={idx} className="space-y-4">
            <h2 className="text-sm font-bold text-slate-300 font-mono uppercase tracking-wider flex items-center justify-between border-b border-slate-800 pb-2">
              <span>{sec.title}</span>
              <span className="text-[11px] text-slate-500 font-normal">{sec.tools.length} Tools</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {sec.tools.map((t) => {
                const Icon = t.icon;

                return (
                  <Link
                    key={t.href}
                    href={t.href}
                    className={`p-5 rounded-xl border bg-gradient-to-br transition-all hover:scale-[1.01] hover:border-cyan-500/50 group flex flex-col justify-between ${t.color}`}
                  >
                    <div>
                      <div className="flex items-start justify-between">
                        <div className="p-2 rounded-lg bg-slate-950/80 border border-slate-800/80">
                          <Icon className="w-5 h-5" />
                        </div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950/90 border border-slate-800 text-slate-400">
                            [{t.key}]
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-950/90 border border-slate-800 text-slate-300">
                            {t.badge}
                          </span>
                        </div>
                      </div>

                      <div className="pt-3 space-y-1">
                        <h3 className="text-sm font-bold text-white group-hover:text-cyan-400 transition-colors flex items-center gap-1">
                          <span>{t.title}</span>
                          <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 group-hover:translate-x-1 transition-all" />
                        </h3>
                        <p className="text-xs text-slate-400 leading-relaxed font-sans">
                          {t.desc}
                        </p>
                      </div>
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Terminal CLI Parity Tip */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 font-mono text-xs">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-cyan-400 font-semibold">
            <Terminal className="w-4 h-4" />
            <span>Companion Ink CLI Terminal</span>
          </div>
          <p className="text-slate-400 text-[11px]">
            Run the interactive terminal console matching all views above with:
          </p>
        </div>
        <div className="px-3 py-2 rounded bg-slate-900 border border-slate-800 text-cyan-300 select-all shrink-0">
          pnpm cli
        </div>
      </div>
    </div>
  );
}
