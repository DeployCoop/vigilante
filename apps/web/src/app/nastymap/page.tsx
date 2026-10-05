'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Radar,
  Globe,
  Table,
  GitCompare,
  Upload,
  Download,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  ShieldAlert,
  Server,
  Terminal,
  Activity,
  ChevronRight,
  X,
  AlertTriangle,
  CheckCircle2
} from 'lucide-react';

export default function NastyMapPage() {
  const [activeTab, setActiveTab] = useState<'topology' | 'geoip' | 'ports' | 'diff'>('topology');
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('');
  const [topologyData, setTopologyData] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [filterMode, setFilterMode] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [diffBase, setDiffBase] = useState<string>('');
  const [diffTarget, setDiffTarget] = useState<string>('');
  const [diffResult, setDiffResult] = useState<any>(null);
  const [diffLoading, setDiffLoading] = useState<boolean>(false);
  const [uploadFeedback, setUploadFeedback] = useState<string | null>(null);

  // Load scans on mount
  useEffect(() => {
    fetch('/api/scans')
      .then((res) => res.json())
      .then((data) => {
        if (data.scans) {
          setScans(data.scans);
          if (data.scans.length > 0) {
            setSelectedScanId(data.scans[0].id || data.scans[0].filename);
            if (data.scans.length >= 2) {
              setDiffBase(data.scans[0].id || data.scans[0].filename);
              setDiffTarget(data.scans[1].id || data.scans[1].filename);
            }
          }
        }
      })
      .catch(() => {});
  }, []);

  // Load topology whenever selectedScanId changes
  useEffect(() => {
    setLoading(true);
    const url = selectedScanId
      ? `/api/nastymap/topology?scanId=${encodeURIComponent(selectedScanId)}&layout=force2d`
      : `/api/nastymap/topology?layout=force2d`;

    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        setTopologyData(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [selectedScanId]);

  // Run Scan Diff
  const handleRunDiff = async () => {
    if (!diffBase || !diffTarget) return;
    setDiffLoading(true);
    try {
      const res = await fetch('/api/scans/diff', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ baseId: diffBase, targetId: diffTarget })
      });
      const data = await res.json();
      setDiffResult(data.diff);
    } catch {
      // Ignore
    } finally {
      setDiffLoading(false);
    }
  };

  // Drag and drop XML upload
  const handleDropXml = async (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const text = await file.text();
      try {
        const res = await fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ xmlContent: text, target: file.name.replace(/\.xml$/, '') })
        });
        const data = await res.json();
        if (data.success) {
          setUploadFeedback(`✔ Uploaded & Parsed: ${file.name}`);
          // Refresh scans
          const scansRes = await fetch('/api/scans');
          const scansData = await scansRes.json();
          setScans(scansData.scans || []);
          setSelectedScanId(data.filename);
        }
      } catch (err: any) {
        setUploadFeedback(`✖ Upload failed: ${err.message}`);
      }
      setTimeout(() => setUploadFeedback(null), 4000);
    }
  };

  const hosts = topologyData?.geocodedHosts || [];
  const filteredHosts = hosts.filter((h: any) => {
    const matchesSearch =
      h.ip.includes(searchQuery) ||
      (h.primaryHostname && h.primaryHostname.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (h.primaryOs && h.primaryOs.toLowerCase().includes(searchQuery.toLowerCase()));

    if (!matchesSearch) return false;
    if (filterMode === 'LIVE') return h.isUp;
    if (filterMode === 'OPEN') return h.openPortsCount > 0;
    if (filterMode === 'VULNS') return (h.vulnerabilitiesCount && h.vulnerabilitiesCount > 0) || h.riskTier === 'CRITICAL' || h.riskTier === 'HIGH';
    return true;
  });

  return (
    <div className="space-y-6" onDragOver={(e) => e.preventDefault()} onDrop={handleDropXml}>
      {/* Top Header & Scan Selector */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Radar className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                NastyMap Network Reconnaissance & Topology
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                  Native 2D Engine
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Target: <span className="font-mono text-cyan-300">{topologyData?.scanTarget || 'Loading network...'}</span> | Total Hosts: <span className="font-mono text-white">{topologyData?.totalHosts || 0}</span> | Open Ports: <span className="font-mono text-white">{topologyData?.totalOpenPorts || 0}</span>
              </p>
            </div>
          </div>
        </div>

        {/* Scan Picker & Mode Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {uploadFeedback && (
            <span className="text-xs font-mono text-emerald-400 px-2 py-1 rounded bg-emerald-950/80 border border-emerald-800">
              {uploadFeedback}
            </span>
          )}

          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg p-1 text-xs font-mono">
            <span className="px-2 text-slate-500">Scan:</span>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="bg-slate-950 text-slate-200 border-none outline-none text-xs rounded px-2 py-1"
            >
              {scans.map((s) => (
                <option key={s.id || s.filename} value={s.id || s.filename}>
                  {s.target || s.filename} ({s.hostsCount || 0} hosts)
                </option>
              ))}
              {scans.length === 0 && <option value="">Default Cluster Network</option>}
            </select>
          </div>

          {/* Export Dropdown */}
          <button
            onClick={() => {
              if (!topologyData?.topology) return;
              const jsonStr = JSON.stringify(topologyData, null, 2);
              const blob = new Blob([jsonStr], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `nastymap-${selectedScanId || 'network'}.json`;
              a.click();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-xs font-mono transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* View Switcher Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800/80">
        <div className="flex items-center gap-1 text-xs font-medium">
          <button
            onClick={() => setActiveTab('topology')}
            className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-mono transition-colors ${
              activeTab === 'topology'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Radar className="w-4 h-4" />
            <span>2D Force Topology</span>
          </button>

          <button
            onClick={() => setActiveTab('geoip')}
            className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-mono transition-colors ${
              activeTab === 'geoip'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>GeoIP World Map</span>
          </button>

          <button
            onClick={() => setActiveTab('ports')}
            className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-mono transition-colors ${
              activeTab === 'ports'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Table className="w-4 h-4" />
            <span>Service & Port Matrix</span>
          </button>

          <button
            onClick={() => setActiveTab('diff')}
            className={`flex items-center gap-2 px-4 py-2.5 border-b-2 font-mono transition-colors ${
              activeTab === 'diff'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitCompare className="w-4 h-4" />
            <span>Scan Diff Explorer</span>
          </button>
        </div>

        {/* Quick Filter chips */}
        {activeTab !== 'diff' && (
          <div className="flex items-center gap-1.5 text-xs font-mono">
            {['ALL', 'LIVE', 'OPEN', 'VULNS'].map((mode) => (
              <button
                key={mode}
                onClick={() => setFilterMode(mode)}
                className={`px-2 py-1 rounded text-[11px] transition-colors ${
                  filterMode === mode
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {mode === 'ALL' && 'All Hosts'}
                {mode === 'LIVE' && '🟢 Live'}
                {mode === 'OPEN' && '🔓 Open Ports'}
                {mode === 'VULNS' && '🛡️ High Risk'}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Main Content Area Based on Active Tab */}

      {/* 1. Topology View */}
      {activeTab === 'topology' && (
        <div className="relative rounded-2xl border border-slate-800 bg-[#070a13] overflow-hidden min-h-[550px] flex">
          {/* Zoom controls overlay */}
          <div className="absolute top-4 left-4 z-20 flex items-center gap-1.5 bg-slate-900/80 border border-slate-800 rounded-lg p-1 text-xs font-mono backdrop-blur-sm">
            <button
              onClick={() => setZoomLevel((z) => Math.max(0.6, z - 0.2))}
              className="w-7 h-7 flex items-center justify-center rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
            >
              -
            </button>
            <span className="px-2 text-slate-300">{Math.round(zoomLevel * 100)}%</span>
            <button
              onClick={() => setZoomLevel((z) => Math.min(2.0, z + 0.2))}
              className="w-7 h-7 flex items-center justify-center rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
            >
              +
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-cyan-400"
            >
              Reset
            </button>
          </div>

          {/* Interactive Topology Graph Canvas / SVG */}
          <div className="flex-1 relative flex items-center justify-center overflow-auto p-8">
            {loading ? (
              <div className="flex flex-col items-center gap-3 text-slate-400 font-mono text-xs">
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
                <span>Computing 2D force topology...</span>
              </div>
            ) : (
              <div
                style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'center center' }}
                className="transition-transform duration-200"
              >
                <svg
                  width="1000"
                  height="600"
                  viewBox="0 0 1000 600"
                  className="rounded-xl overflow-visible"
                >
                  <defs>
                    <radialGradient id="netGlow" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stop-color="#1e1b4b" stop-opacity="0.6" />
                      <stop offset="100%" stop-color="#070a13" stop-opacity="0" />
                    </radialGradient>
                  </defs>

                  {/* Background Radar Rings */}
                  <circle cx="500" cy="300" r="120" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="4,4" />
                  <circle cx="500" cy="300" r="220" fill="none" stroke="#1e293b" strokeWidth="1" strokeDasharray="4,4" />
                  <circle cx="500" cy="300" r="280" fill="url(#netGlow)" />

                  {/* Links / Edges */}
                  {(topologyData?.topology?.links || []).map((link: any, i: number) => {
                    const sourceNode = topologyData.topology.nodes.find((n: any) => n.id === (link.source?.id || link.source));
                    const targetNode = topologyData.topology.nodes.find((n: any) => n.id === (link.target?.id || link.target));
                    if (!sourceNode || !targetNode) return null;

                    const isLateral = link.type === 'lateral-attack-path';
                    const isTraceroute = link.type === 'traceroute';

                    return (
                      <g key={i}>
                        <line
                          x1={sourceNode.x}
                          y1={sourceNode.y}
                          x2={targetNode.x}
                          y2={targetNode.y}
                          stroke={isLateral ? '#ef4444' : isTraceroute ? '#06b6d4' : '#475569'}
                          strokeWidth={isLateral ? 2.5 : isTraceroute ? 1.8 : 1.2}
                          strokeDasharray={isLateral ? '6,3' : link.type === 'subnet' ? '4,4' : undefined}
                          opacity={0.7}
                        />
                        {link.label && (
                          <text
                            x={(sourceNode.x + targetNode.x) / 2}
                            y={(sourceNode.y + targetNode.y) / 2 - 4}
                            fill={isLateral ? '#f87171' : '#94a3b8'}
                            fontSize="9"
                            fontFamily="monospace"
                            textAnchor="middle"
                          >
                            {link.label}
                          </text>
                        )}
                      </g>
                    );
                  })}

                  {/* Nodes */}
                  {(topologyData?.topology?.nodes || []).map((node: any) => {
                    const isSelected = selectedNode?.id === node.id || selectedNode?.ip === node.ip;
                    const isScanner = node.nodeType === 'scanner';
                    const isCrit = node.riskTier === 'CRITICAL';
                    const isHigh = node.riskTier === 'HIGH';

                    const strokeColor = isCrit ? '#ef4444' : isHigh ? '#f59e0b' : node.status === 'up' ? '#10b981' : '#64748b';
                    const fillColor = isScanner ? '#8b5cf6' : node.color || '#0284c7';

                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        onClick={() => {
                          const matchedHost = hosts.find((h: any) => h.ip === node.ip) || node;
                          setSelectedNode(matchedHost);
                        }}
                        className="cursor-pointer transition-all hover:opacity-100"
                      >
                        {/* Glow halo if critical */}
                        {isCrit && (
                          <circle r={node.radius + 8} fill="none" stroke="#ef4444" strokeWidth="1.5" className="animate-pulse" opacity="0.6" />
                        )}
                        {isSelected && (
                          <circle r={node.radius + 6} fill="none" stroke="#06b6d4" strokeWidth="2" strokeDasharray="3,3" />
                        )}

                        <circle
                          r={node.radius || 18}
                          fill={fillColor}
                          stroke={strokeColor}
                          strokeWidth={isSelected ? 3 : 2}
                        />

                        {/* Label */}
                        <text
                          y={node.radius + 14}
                          fill="#f8fafc"
                          fontSize="10"
                          fontFamily="sans-serif"
                          fontWeight="600"
                          textAnchor="middle"
                        >
                          {node.label || node.ip}
                        </text>

                        {/* IP subtitle */}
                        <text
                          y={node.radius + 25}
                          fill="#94a3b8"
                          fontSize="8"
                          fontFamily="monospace"
                          textAnchor="middle"
                        >
                          {node.ip}
                        </text>

                        {/* Risk score badge */}
                        {typeof node.riskScore === 'number' && (
                          <text
                            y={node.radius + 36}
                            fill={isCrit ? '#f87171' : isHigh ? '#fbbf24' : '#34d399'}
                            fontSize="8"
                            fontFamily="monospace"
                            fontWeight="bold"
                            textAnchor="middle"
                          >
                            {node.riskScore}/100 [{node.riskTier || 'CLEAN'}]
                          </text>
                        )}
                      </g>
                    );
                  })}
                </svg>
              </div>
            )}
          </div>

          {/* Node Inspector Drawer */}
          {selectedNode && (
            <div className="w-80 border-l border-slate-800 bg-slate-950/90 p-5 overflow-y-auto space-y-4 shrink-0 backdrop-blur-md">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  <span className="font-bold text-white text-sm font-mono">{selectedNode.ip}</span>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Host Attributes */}
              <div className="space-y-2 text-xs font-mono">
                <div>
                  <span className="text-slate-500">Hostname:</span>
                  <div className="text-slate-200">{selectedNode.primaryHostname || selectedNode.label || 'N/A'}</div>
                </div>
                <div>
                  <span className="text-slate-500">OS Family:</span>
                  <div className="text-slate-200">{selectedNode.primaryOs || selectedNode.osFamily || 'Unknown'}</div>
                </div>
                <div>
                  <span className="text-slate-500">Risk Assessment:</span>
                  <div className="flex items-center gap-2 pt-0.5">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                      selectedNode.riskTier === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                      selectedNode.riskTier === 'HIGH' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                      'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      {selectedNode.riskScore || 0}/100 [{selectedNode.riskTier || 'CLEAN'}]
                    </span>
                  </div>
                </div>
              </div>

              {/* Open Ports */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="text-xs font-mono font-semibold text-slate-300 flex items-center justify-between">
                  <span>Open Ports ({selectedNode.openPorts?.length || 0})</span>
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {(selectedNode.openPorts || []).map((p: any, i: number) => (
                    <div key={i} className="p-2 rounded bg-slate-900 border border-slate-800/80 text-[11px] font-mono">
                      <div className="flex items-center justify-between text-cyan-400">
                        <span>{p.port}/{p.protocol}</span>
                        <span className="text-emerald-400 text-[10px]">{p.service}</span>
                      </div>
                      <div className="text-slate-400 text-[10px] truncate">{p.product} {p.version}</div>
                    </div>
                  ))}
                  {(!selectedNode.openPorts || selectedNode.openPorts.length === 0) && (
                    <div className="text-slate-500 text-xs italic">No open ports discovered</div>
                  )}
                </div>
              </div>

              {/* GeoIP Info */}
              {selectedNode.geo && (
                <div className="pt-2 border-t border-slate-800 text-xs font-mono space-y-1">
                  <div className="text-slate-400 font-semibold">GeoIP Location</div>
                  <div className="text-slate-300">{selectedNode.geo.city || 'Private LAN'}, {selectedNode.geo.country || 'RFC 1918'}</div>
                  <div className="text-slate-500 text-[10px]">ISP: {selectedNode.geo.isp || 'Internal Network'}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 2. GeoIP World Map View */}
      {activeTab === 'geoip' && (
        <div className="rounded-2xl border border-slate-800 bg-[#070a13] p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                Global Infrastructure & Target Distribution
              </h2>
              <p className="text-xs text-slate-400">
                Visualizing geocoded IP coordinates, RFC 1918 internal subnets, and external adversary C2 nodes.
              </p>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Resolved: <strong className="text-cyan-400">{hosts.length}</strong> hosts
            </div>
          </div>

          {/* World Vector Visualizer */}
          <div className="relative rounded-xl border border-slate-800 bg-slate-950 p-6 overflow-hidden min-h-[420px] flex flex-col justify-between">
            <svg viewBox="0 0 1000 500" className="w-full h-auto opacity-70">
              {/* World outline grid */}
              <line x1="0" y1="250" x2="1000" y2="250" stroke="#1e293b" strokeWidth="1" strokeDasharray="3,3" />
              <line x1="500" y1="0" x2="500" y2="500" stroke="#1e293b" strokeWidth="1" strokeDasharray="3,3" />
              <rect x="50" y="50" width="900" height="400" fill="none" stroke="#0f172a" strokeWidth="1" />

              {/* Continents rough vector silhouette */}
              <path
                d="M150,120 Q220,100 280,140 Q320,200 240,260 Q180,240 140,180 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />
              <path
                d="M450,110 Q550,90 620,130 Q580,220 500,240 Q430,200 440,140 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />
              <path
                d="M650,140 Q780,120 850,190 Q820,300 700,320 Q640,240 650,160 Z"
                fill="#0f172a"
                stroke="#1e293b"
                strokeWidth="1.5"
              />

              {/* Host Markers */}
              {hosts.map((h: any, i: number) => {
                const isPrivate = h.geo?.isPrivate || !h.geo?.latitude;
                // Place private LAN hosts in a clustered datacenter representation
                const cx = isPrivate ? 200 + (i * 35) % 150 : 500 + ((h.geo.longitude || 0) * 2.5);
                const cy = isPrivate ? 200 + (i * 25) % 100 : 250 - ((h.geo.latitude || 0) * 2.5);
                const isCrit = h.riskTier === 'CRITICAL';

                return (
                  <g key={i} className="cursor-pointer group">
                    {isCrit && (
                      <circle cx={cx} cy={cy} r="14" fill="none" stroke="#ef4444" strokeWidth="1.5" className="animate-ping" opacity="0.6" />
                    )}
                    <circle
                      cx={cx}
                      cy={cy}
                      r={isCrit ? 7 : 5}
                      fill={isCrit ? '#ef4444' : isPrivate ? '#06b6d4' : '#10b981'}
                      stroke="#070a13"
                      strokeWidth="2"
                    />
                    <text
                      x={cx}
                      y={cy - 10}
                      fill="#f8fafc"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      {h.ip} ({h.geo?.country || 'LAN'})
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* GeoIP Host Table Summary */}
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 pt-4 border-t border-slate-900">
              {hosts.slice(0, 4).map((h: any, i: number) => (
                <div key={i} className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
                  <div className="flex items-center justify-between text-white font-semibold">
                    <span>{h.ip}</span>
                    <span className="text-[10px] text-cyan-400">{h.geo?.countryCode || 'LAN'}</span>
                  </div>
                  <div className="text-slate-400 text-[11px] truncate">{h.geo?.city || 'Internal Subnet'}, {h.geo?.country || 'RFC 1918'}</div>
                  <div className="text-slate-500 text-[10px] pt-1">Open: {h.openPortsCount} ports</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 3. Service & Port Matrix View */}
      {activeTab === 'ports' && (
        <div className="rounded-2xl border border-slate-800 bg-[#070a13] p-6 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search hosts, ports, products, or CVEs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs font-mono text-slate-200 outline-none focus:border-cyan-500"
              />
            </div>

            <div className="text-xs font-mono text-slate-400">
              Showing <strong className="text-white">{filteredHosts.length}</strong> hosts
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4 font-semibold">Host IP</th>
                  <th className="py-3 px-4 font-semibold">Hostname</th>
                  <th className="py-3 px-4 font-semibold">OS Family</th>
                  <th className="py-3 px-4 font-semibold">Open Ports & Services</th>
                  <th className="py-3 px-4 font-semibold">Risk Tier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950/40 text-slate-300">
                {filteredHosts.map((h: any, idx: number) => (
                  <tr key={idx} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-3 px-4 font-bold text-white flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${h.isUp ? 'bg-emerald-500' : 'bg-rose-500'}`}></span>
                      {h.ip}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{h.primaryHostname || 'None'}</td>
                    <td className="py-3 px-4">{h.primaryOs || h.osFamily || 'Unknown'}</td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1.5">
                        {(h.openPorts || []).map((p: any, pIdx: number) => (
                          <span
                            key={pIdx}
                            className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] text-cyan-300"
                          >
                            {p.port}/{p.protocol} ({p.service})
                          </span>
                        ))}
                        {(!h.openPorts || h.openPorts.length === 0) && (
                          <span className="text-slate-600 text-[11px]">No open ports</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          h.riskTier === 'CRITICAL'
                            ? 'bg-rose-950 text-rose-400 border border-rose-800'
                            : h.riskTier === 'HIGH'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}
                      >
                        {h.riskScore || 0}/100 [{h.riskTier || 'CLEAN'}]
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 4. Scan Diff Explorer View */}
      {activeTab === 'diff' && (
        <div className="rounded-2xl border border-slate-800 bg-[#070a13] p-6 space-y-6">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <GitCompare className="w-5 h-5 text-cyan-400" />
              Side-by-Side Nmap Scan Comparison Engine
            </h2>
            <p className="text-xs text-slate-400">
              Detects newly discovered hosts, closed/filtered ports, and altered service versions across two scan timestamps.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <label className="text-xs font-mono text-slate-400">Base Scan (Historical Baseline):</label>
              <select
                value={diffBase}
                onChange={(e) => setDiffBase(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg p-2 font-mono"
              >
                {scans.map((s) => (
                  <option key={s.id || s.filename} value={s.id || s.filename}>
                    {s.target} - {s.filename}
                  </option>
                ))}
              </select>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
              <label className="text-xs font-mono text-slate-400">Target Scan (Recent Audit):</label>
              <select
                value={diffTarget}
                onChange={(e) => setDiffTarget(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg p-2 font-mono"
              >
                {scans.map((s) => (
                  <option key={s.id || s.filename} value={s.id || s.filename}>
                    {s.target} - {s.filename}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex justify-center">
            <button
              onClick={handleRunDiff}
              disabled={diffLoading || !diffBase || !diffTarget}
              className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${diffLoading ? 'animate-spin' : ''}`} />
              <span>Compute Scan Differences</span>
            </button>
          </div>

          {/* Diff Results Container */}
          {diffResult && (
            <div className="space-y-4 pt-4 border-t border-slate-800">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-900 text-xs font-mono">
                  <span className="text-emerald-400 font-bold">New Discovered Hosts</span>
                  <div className="text-xl font-bold text-white pt-1">{diffResult.newHosts?.length || 0}</div>
                </div>
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900 text-xs font-mono">
                  <span className="text-rose-400 font-bold">Disappeared Hosts</span>
                  <div className="text-xl font-bold text-white pt-1">{diffResult.removedHosts?.length || 0}</div>
                </div>
                <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-900 text-xs font-mono">
                  <span className="text-amber-400 font-bold">Modified Services</span>
                  <div className="text-xl font-bold text-white pt-1">{diffResult.modifiedHosts?.length || 0}</div>
                </div>
              </div>

              {/* Detailed Host Diff List */}
              <div className="space-y-2">
                {(diffResult.newHosts || []).map((h: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/60 flex items-center justify-between text-xs font-mono">
                    <span className="text-emerald-300 font-bold">+ NEW HOST: {h.ip} ({h.primaryHostname || 'No hostname'})</span>
                    <span className="text-emerald-400">{h.openPortsCount} open ports</span>
                  </div>
                ))}
                {(diffResult.removedHosts || []).map((h: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-rose-950/20 border border-rose-800/60 flex items-center justify-between text-xs font-mono">
                    <span className="text-rose-300 font-bold">- REMOVED HOST: {h.ip}</span>
                    <span className="text-rose-400">Offline / Filtered</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
