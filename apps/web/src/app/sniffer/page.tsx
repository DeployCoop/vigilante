'use client';

import React, { useState, useEffect } from 'react';
import {
  Radio,
  Play,
  Pause,
  RefreshCw,
  Filter,
  Download,
  Terminal,
  Activity,
  ChevronRight,
  ChevronDown,
  Layers,
  FileText
} from 'lucide-react';

interface Packet {
  id: number;
  index: number;
  timestamp: string;
  src: string;
  dst: string;
  protocol: string;
  length: number;
  info: string;
  ethernet: any;
  ip: any;
  tcp: any;
  udp: any;
  dns: any;
  tls: any;
  hexDump: string;
}

export default function SnifferPage() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [filter, setFilter] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [exportedStatus, setExportedStatus] = useState<string | null>(null);

  const fetchPackets = () => {
    fetch(`/api/sniffer?filter=${filter}`)
      .then((res) => res.json())
      .then((d) => {
        if (d.success) {
          setPackets(d.packets || []);
          if (!selectedPacket && d.packets?.length > 0) {
            setSelectedPacket(d.packets[0]);
          }
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));
  };

  useEffect(() => {
    fetchPackets();
    const interval = setInterval(() => {
      if (!isPaused) {
        fetchPackets();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [isPaused, filter]);

  const handleExportPcap = async () => {
    try {
      const res = await fetch('/api/sniffer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: packets.length })
      });
      const data = await res.json();
      if (data.success) {
        setExportedStatus(`Saved ${data.packetCount} packets (${data.bytesWritten} bytes) to ${data.pcapPath}`);
        setTimeout(() => setExportedStatus(null), 4000);
      }
    } catch (err: any) {
      setExportedStatus(`Error: ${err.message}`);
    }
  };

  const getProtocolColor = (proto: string) => {
    switch (proto?.toUpperCase()) {
      case 'TCP':
        return 'text-cyan-400 bg-cyan-950/80 border-cyan-800';
      case 'UDP':
        return 'text-purple-400 bg-purple-950/80 border-purple-800';
      case 'DNS':
        return 'text-emerald-400 bg-emerald-950/80 border-emerald-800';
      case 'TLS':
        return 'text-amber-400 bg-amber-950/80 border-amber-800';
      case 'HTTP':
        return 'text-sky-400 bg-sky-950/80 border-sky-800';
      default:
        return 'text-slate-400 bg-slate-900 border-slate-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-teal-500/10 border border-teal-500/30 text-teal-400">
            <Radio className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              Live Network Packet Sniffer & Dissector
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-teal-950 border border-teal-800 text-teal-300">
                Wireshark Web View
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Live Ethernet/IP/TCP/UDP/DNS/TLS dissection, BPF protocol filtering, side-by-side hex dump, and PCAP export.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border transition-colors ${
              isPaused
                ? 'bg-amber-950/80 border-amber-800 text-amber-300'
                : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume Sniffer' : 'Pause'}</span>
          </button>

          <button
            onClick={handleExportPcap}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-teal-950/80 hover:bg-teal-900 text-teal-300 border border-teal-800 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export PCAP</span>
          </button>
        </div>
      </div>

      {exportedStatus && (
        <div className="p-3 rounded-lg bg-teal-950/60 border border-teal-800 text-teal-300 font-mono text-xs">
          {exportedStatus}
        </div>
      )}

      {/* Protocol Filter Tabs */}
      <div className="flex items-center gap-2 bg-slate-900/60 p-2 rounded-xl border border-slate-800 font-mono text-xs">
        <span className="text-slate-500 pl-2">Filter:</span>
        {['', 'dns', 'tls', 'tcp', 'udp'].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded-lg transition-colors ${
              filter === f
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            {f ? f.toUpperCase() : 'ALL PACKETS'}
          </button>
        ))}
      </div>

      {/* Top: Packet List Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden font-mono text-xs">
        <div className="max-h-64 overflow-y-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px] sticky top-0">
              <tr>
                <th className="py-2.5 px-3">#</th>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Destination</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Length</th>
                <th className="py-2.5 px-3">Info</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {packets.map((p) => (
                <tr
                  key={p.id}
                  onClick={() => setSelectedPacket(p)}
                  className={`cursor-pointer transition-colors ${
                    selectedPacket?.id === p.id ? 'bg-cyan-950/50 text-white font-medium' : 'hover:bg-slate-900/40'
                  }`}
                >
                  <td className="py-2 px-3 text-slate-500">{p.id}</td>
                  <td className="py-2 px-3 text-slate-400">{new Date(p.timestamp).toLocaleTimeString()}</td>
                  <td className="py-2 px-3 text-cyan-400">{p.src}</td>
                  <td className="py-2 px-3 text-slate-300">{p.dst}</td>
                  <td className="py-2 px-3">
                    <span className={`px-1.5 py-0.2 rounded border text-[10px] ${getProtocolColor(p.protocol)}`}>
                      {p.protocol}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-400">{p.length} B</td>
                  <td className="py-2 px-3 text-slate-300 truncate max-w-[280px]">{p.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom Split: Protocol Tree & Hex Dump */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs">
        {/* Protocol Dissection Tree */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
          <div className="text-slate-400 font-bold uppercase text-[11px] pb-2 border-b border-slate-800 flex items-center justify-between">
            <span>Protocol Hierarchy Dissection</span>
            <span className="text-cyan-400">Frame {selectedPacket?.id || 1}</span>
          </div>

          {selectedPacket ? (
            <div className="space-y-2 text-[11px] leading-relaxed">
              {/* Ethernet */}
              <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="font-bold text-white flex items-center gap-1.5">
                  <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Ethernet II, Src: {selectedPacket.ethernet?.srcMac}, Dst: {selectedPacket.ethernet?.dstMac}</span>
                </div>
                <div className="pl-5 text-slate-400 text-[10px]">
                  Type: {selectedPacket.ethernet?.typeName || 'IPv4'}
                </div>
              </div>

              {/* IP */}
              {selectedPacket.ip && (
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 space-y-1">
                  <div className="font-bold text-white flex items-center gap-1.5">
                    <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Internet Protocol Version 4, Src: {selectedPacket.ip.srcIp}, Dst: {selectedPacket.ip.dstIp}</span>
                  </div>
                  <div className="pl-5 text-slate-400 text-[10px]">
                    Protocol: {selectedPacket.ip.protocolName} | TTL: {selectedPacket.ip.ttl}
                  </div>
                </div>
              )}

              {/* TCP / UDP */}
              {selectedPacket.tcp && (
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 space-y-1">
                  <div className="font-bold text-white flex items-center gap-1.5">
                    <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Transmission Control Protocol, Src Port: {selectedPacket.tcp.srcPort}, Dst Port: {selectedPacket.tcp.dstPort}</span>
                  </div>
                  <div className="pl-5 text-slate-400 text-[10px]">
                    Flags: {selectedPacket.tcp.flags?.join(', ')} | Seq: {selectedPacket.tcp.seqNumber}
                  </div>
                </div>
              )}

              {/* TLS */}
              {selectedPacket.tls && (
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 space-y-1">
                  <div className="font-bold text-amber-400 flex items-center gap-1.5">
                    <ChevronDown className="w-3.5 h-3.5" />
                    <span>Transport Layer Security (TLS Handshake)</span>
                  </div>
                  <div className="pl-5 text-slate-400 text-[10px]">
                    Type: Client Hello {selectedPacket.tls.sni ? `| SNI: ${selectedPacket.tls.sni}` : ''}
                  </div>
                </div>
              )}

              {/* DNS */}
              {selectedPacket.dns && (
                <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800 space-y-1">
                  <div className="font-bold text-emerald-400 flex items-center gap-1.5">
                    <ChevronDown className="w-3.5 h-3.5" />
                    <span>Domain Name System ({selectedPacket.dns.isResponse ? 'Response' : 'Query'})</span>
                  </div>
                  <div className="pl-5 text-slate-400 text-[10px]">
                    Name: {selectedPacket.dns.queryName} | Type: {selectedPacket.dns.queryType}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500">Select a packet from the stream above.</div>
          )}
        </div>

        {/* Side-by-side Hex & ASCII Dump */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/60 space-y-3">
          <div className="text-slate-400 font-bold uppercase text-[11px] pb-2 border-b border-slate-800 flex items-center justify-between">
            <span>Hex Dump & ASCII Inspector</span>
            <span>Offset / Hex / ASCII</span>
          </div>

          <pre className="p-3 rounded-lg bg-black/70 border border-slate-900 text-cyan-300 font-mono text-[11px] leading-relaxed max-h-72 overflow-y-auto selection:bg-cyan-500/30">
            {selectedPacket?.hexDump || 'No payload bytes'}
          </pre>
        </div>
      </div>
    </div>
  );
}
