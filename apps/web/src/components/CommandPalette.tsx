'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  Search,
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
  X,
  Sparkles,
  Key
} from 'lucide-react';

export const COMMAND_ITEMS = [
  // Event
  { href: '/intro', label: 'Agents Hunting Agents: Vigil-SOC Setup Guide', section: 'Event: Hands-on Lab', icon: Sparkles, key: 'i' },

  // Settings & Access
  { href: '/settings/access', label: 'Access Control & Security Audit (CASL RBAC)', section: 'Settings & Administration', icon: Key, key: 'a' },

  // Phase 1: Preparation
  { href: '/', label: 'Operations Hub Dashboard', section: 'NIST Phase 1: Preparation & Readiness', icon: Activity, key: '1' },
  { href: '/instances', label: 'Cluster Instances Manager', section: 'NIST Phase 1: Preparation & Readiness', icon: Server, key: '3' },
  { href: '/values', label: 'Helm Values Editor & Overrides', section: 'NIST Phase 1: Preparation & Readiness', icon: FileCode, key: '4' },

  // Phase 2: Detection & Analysis
  { href: '/nastymap', label: 'NastyMap Reconnaissance & Topology', section: 'NIST Phase 2: Detection & Analysis', icon: Radar, key: '5' },
  { href: '/analyst', label: 'AI Security Analyst (NIST Triage)', section: 'NIST Phase 2: Detection & Analysis', icon: Cpu, key: '7' },
  { href: '/pods', label: 'Kubernetes Live Pods & Workload Monitor', section: 'NIST Phase 2: Detection & Analysis', icon: Server, key: '8' },
  { href: '/openvas', label: 'OpenVAS / Greenbone Vulnerability Scanner', section: 'NIST Phase 2: Detection & Analysis', icon: ShieldAlert, key: 'o' },
  { href: '/oobscan', label: 'OOBscan BMC & Hardware Security Audit', section: 'NIST Phase 2: Detection & Analysis', icon: Cpu, key: 'b' },
  { href: '/vuln', label: 'Vulnerability Center & Threat Dossiers', section: 'NIST Phase 2: Detection & Analysis', icon: ShieldAlert, key: 'v' },
  { href: '/battlestation', label: 'BattleStation Live SOC (eBPF & IDS)', section: 'NIST Phase 2: Detection & Analysis', icon: Radio, key: 'l' },
  { href: '/posture', label: 'KSPM Security Posture & CIS Scorecard', section: 'NIST Phase 2: Detection & Analysis', icon: ShieldAlert, key: 'k' },
  { href: '/forensics', label: 'PCAP Forensics & Protocol Reconstruction', section: 'NIST Phase 2: Detection & Analysis', icon: FileSearch, key: 'z' },
  { href: '/lineage', label: 'Kernel eBPF Process Lineage Tree', section: 'NIST Phase 2: Detection & Analysis', icon: GitFork, key: 'e' },
  { href: '/cloudsec', label: 'Multi-Cloud Workload Identity & CSPM', section: 'NIST Phase 2: Detection & Analysis', icon: Cloud, key: 'c' },
  { href: '/timeline', label: 'Attack Timeline & Causal DAG Explorer', section: 'NIST Phase 2: Detection & Analysis', icon: Clock, key: 't' },
  { href: '/sniffer', label: 'Terminal Live Packet Sniffer & Dissector', section: 'NIST Phase 2: Detection & Analysis', icon: Radio, key: 'u' },
  { href: '/graph', label: 'Composite Attack Graph & Kill Chains', section: 'NIST Phase 2: Detection & Analysis', icon: Share2, key: 'x' },

  // Phase 3: Containment, Eradication & Recovery
  { href: '/audit', label: 'Shift-Left CI/CD Security Audit', section: 'NIST Phase 3: Containment & Simulation', icon: FileCheck2, key: 'g' },
  { href: '/deception', label: 'Autonomous Deception Mesh (Canary Kube)', section: 'NIST Phase 3: Containment & Simulation', icon: ShieldAlert, key: 'y' },
  { href: '/purpleteam', label: 'Autonomous Purple Team Arena (Wargames)', section: 'NIST Phase 3: Containment & Simulation', icon: Swords, key: 'w' },
  { href: '/threatsim', label: 'Threat Simulation Engine & Attack Playbooks', section: 'NIST Phase 3: Containment & Simulation', icon: Flame, key: '9' },
  { href: '/ctf', label: 'kCTF Cyber Range & Arena Spin-Up', section: 'NIST Phase 3: Containment & Simulation', icon: Flag, key: 'f' },
  { href: '/modules', label: 'Security Modules & Multi-Tenant Stacks', section: 'NIST Phase 3: Containment & Simulation', icon: Layers, key: '0' },
];

export function CommandPalette({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const router = useRouter();
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  const filteredItems = COMMAND_ITEMS.filter((item) =>
    item.label.toLowerCase().includes(query.toLowerCase()) ||
    item.section.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'p')) {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose(); // parent handles toggle
      }

      if (!isOpen) return;

      if (e.key === 'Escape') {
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev < filteredItems.length - 1 ? prev + 1 : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : filteredItems.length - 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filteredItems[selectedIndex]) {
          router.push(filteredItems[selectedIndex].href);
          onClose();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filteredItems, selectedIndex, router, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-start justify-center pt-20 p-4">
      <div className="w-full max-w-2xl bg-slate-950 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col font-mono text-xs">
        {/* Search Input */}
        <div className="p-3 border-b border-slate-800 flex items-center gap-3 bg-slate-900/60">
          <Search className="w-4 h-4 text-cyan-400 shrink-0" />
          <input
            type="text"
            placeholder="Type a tool name, NIST phase, or shortcut to jump..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            className="w-full bg-transparent border-none text-slate-100 placeholder-slate-500 focus:outline-none text-xs"
          />
          <button onClick={onClose} className="text-slate-500 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results */}
        <div className="max-h-96 overflow-y-auto p-2 space-y-1">
          {filteredItems.length === 0 ? (
            <div className="p-6 text-center text-slate-500">No matching operations tools found.</div>
          ) : (
            filteredItems.map((item, idx) => {
              const Icon = item.icon;
              const isSelected = idx === selectedIndex;

              return (
                <div
                  key={item.href}
                  onClick={() => {
                    router.push(item.href);
                    onClose();
                  }}
                  className={`p-3 rounded-lg flex items-center justify-between cursor-pointer transition-colors ${
                    isSelected ? 'bg-cyan-950/60 text-white' : 'hover:bg-slate-900/50 text-slate-400'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`p-1.5 rounded ${isSelected ? 'bg-cyan-500/20 text-cyan-400' : 'bg-slate-900 text-slate-500'}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="font-bold text-slate-200">{item.label}</div>
                      <div className="text-[10px] text-slate-500">{item.section}</div>
                    </div>
                  </div>

                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                    [{item.key}]
                  </span>
                </div>
              );
            })
          )}
        </div>

        {/* Footer */}
        <div className="p-2.5 bg-slate-900/60 border-t border-slate-800 text-[10px] text-slate-500 flex items-center justify-between">
          <span>Navigate with ↑ / ↓, select with Enter</span>
          <span>Esc to exit</span>
        </div>
      </div>
    </div>
  );
}
