'use client';

import React, { useState, useEffect } from 'react';
import {
  Radio,
  ShieldAlert,
  Terminal,
  Activity,
  Filter,
  Play,
  Pause,
  AlertTriangle,
  Server,
  Network,
  ChevronDown
} from 'lucide-react';

export default function BattleStationPage() {
  const [events, setEvents] = useState<any[]>([]);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedEvent, setSelectedEvent] = useState<any>(null);

  useEffect(() => {
    if (!isStreaming) return;

    const eventSource = new EventSource('/api/events/stream');

    eventSource.addEventListener('telemetry', (e) => {
      try {
        const item = JSON.parse(e.data);
        setEvents((prev) => [item, ...prev].slice(0, 100));
      } catch {
        // Ignore parse error
      }
    });

    return () => {
      eventSource.close();
    };
  }, [isStreaming]);

  const filteredEvents = events.filter((ev) => {
    if (severityFilter === 'ALL') return true;
    return ev.severity === severityFilter;
  });

  const falcoEvents = filteredEvents.filter((e) => e.source === 'falco');
  const networkEvents = filteredEvents.filter((e) => e.source === 'suricata' || e.source === 'zeek');

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              BattleStation Live SOC Telemetry
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 border border-rose-800 text-rose-300">
                {isStreaming ? 'STREAMING ACTIVE' : 'PAUSED'}
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Correlating kernel-level eBPF syscalls with live Zeek & Suricata network flow telemetry.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Severity filter */}
          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-mono">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-1 rounded text-[11px] ${
                  severityFilter === sev
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Pause / Play */}
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 transition-colors"
          >
            {isStreaming ? <Pause className="w-3.5 h-3.5 text-amber-400" /> : <Play className="w-3.5 h-3.5 text-emerald-400" />}
            <span>{isStreaming ? 'Pause Stream' : 'Resume'}</span>
          </button>
        </div>
      </div>

      {/* Dual Pane Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[550px]">
        {/* Left Pane: eBPF Falco Runtime Security */}
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2 text-white font-bold text-sm">
              <Server className="w-4 h-4 text-purple-400" />
              <span>eBPF Runtime Defense (Falco)</span>
            </div>
            <span className="text-xs font-mono text-purple-400">{falcoEvents.length} events</span>
          </div>

          <div className="flex-1 space-y-2 overflow-y-auto max-h-[500px]">
            {falcoEvents.map((ev, i) => (
              <div
                key={ev.id || i}
                onClick={() => setSelectedEvent(ev)}
                className={`p-3 rounded-lg border text-xs font-mono transition-all cursor-pointer ${
                  selectedEvent?.id === ev.id
                    ? 'bg-purple-950/40 border-purple-500/60'
                    : 'bg-slate-900/40 border-slate-800 hover:bg-slate-900/80'
                }`}
              >
                <div className="flex items-center justify-between pb-1">
                  <span className="text-purple-400 font-semibold">{ev.rule}</span>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] ${
                    ev.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    {ev.severity}
                  </span>
                </div>
                <div className="text-slate-400 text-[11px] truncate">{ev.message}</div>
                <div className="text-slate-500 text-[10px] pt-1 flex justify-between">
                  <span>Pod: {ev.container}</span>
                  <span>{new Date(ev.time).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
            {falcoEvents.length === 0 && (
              <div className="text-slate-500 text-xs italic text-center py-12">Listening for container syscall anomalies...</div>
            )}
          </div>
        </div>

        {/* Right Pane: Network Flow & IDS (Zeek / Suricata) */}
        <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-5 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2 text-white font-bold text-sm">
              <Network className="w-4 h-4 text-cyan-400" />
              <span>Network IDS & Flows (Suricata & Zeek)</span>
            </div>
            <span className="text-xs font-mono text-cyan-400">{networkEvents.length} alerts</span>
          </div>

          <div className="flex-1 space-y-2 overflow-y-auto max-h-[500px]">
            {networkEvents.map((ev, i) => (
              <div
                key={ev.id || i}
                onClick={() => setSelectedEvent(ev)}
                className={`p-3 rounded-lg border text-xs font-mono transition-all cursor-pointer ${
                  selectedEvent?.id === ev.id
                    ? 'bg-cyan-950/40 border-cyan-500/60'
                    : 'bg-slate-900/40 border-slate-800 hover:bg-slate-900/80'
                }`}
              >
                <div className="flex items-center justify-between pb-1">
                  <span className="text-cyan-400 font-semibold">{ev.rule}</span>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] ${
                    ev.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    ev.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {ev.severity}
                  </span>
                </div>
                <div className="text-slate-400 text-[11px] truncate">{ev.message}</div>
                <div className="text-slate-500 text-[10px] pt-1 flex justify-between">
                  <span>Flow: {ev.srcIp} ➔ {ev.destIp}</span>
                  <span>{new Date(ev.time).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
            {networkEvents.length === 0 && (
              <div className="text-slate-500 text-xs italic text-center py-12">Monitoring packet streams for signatures...</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
