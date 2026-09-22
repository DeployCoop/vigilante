/**
 * NastyMap Standalone Exporter
 * Generates Headless SVG Vector Maps and Standalone HTML Reports.
 */

/**
 * Generates an SVG string representation of a TopologyGraph without requiring a DOM.
 * @param {Object} graph TopologyGraph { nodes: [], links: [] }
 * @param {Object} [options]
 * @returns {string} SVG XML content
 */
export function generateHeadlessSvg(graph, options = {}) {
  const width = options.width || 1200;
  const height = options.height || 800;
  const title = options.title || 'Nmap Network Topology Map';

  const nodeMap = new Map();
  for (const n of graph.nodes || []) nodeMap.set(n.id, n);

  let linksSvg = '';
  for (const link of graph.links || []) {
    const sId = typeof link.source === 'string' ? link.source : link.source?.id;
    const tId = typeof link.target === 'string' ? link.target : link.target?.id;
    const s = nodeMap.get(sId);
    const t = nodeMap.get(tId);
    if (!s || !t) continue;

    const strokeColor = link.type === 'traceroute' ? '#38bdf8' : '#64748b';
    const strokeWidth = link.type === 'traceroute' ? 2 : 1.5;
    const strokeDash = link.type === 'subnet' ? 'stroke-dasharray="4,4"' : '';

    linksSvg += `
      <line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="${strokeColor}" stroke-width="${strokeWidth}" ${strokeDash} opacity="0.6" />
    `;

    if (link.label) {
      const midX = (s.x + t.x) / 2;
      const midY = (s.y + t.y) / 2;
      linksSvg += `
        <text x="${midX}" y="${midY - 4}" fill="#94a3b8" font-size="10" font-family="monospace" text-anchor="middle">${link.label}</text>
      `;
    }
  }

  let nodesSvg = '';
  for (const node of graph.nodes || []) {
    const isScanner = node.nodeType === 'scanner';
    const fill = node.color || '#3b82f6';
    const stroke = isScanner ? '#a855f7' : node.status === 'up' ? '#22c55e' : '#ef4444';

    nodesSvg += `
      <g transform="translate(${node.x}, ${node.y})">
        <circle r="${node.radius}" fill="${fill}" stroke="${stroke}" stroke-width="2.5" />
        <text y="${node.radius + 14}" fill="#f8fafc" font-size="11" font-family="system-ui, sans-serif" font-weight="600" text-anchor="middle">${node.label}</text>
        <text y="${node.radius + 26}" fill="#94a3b8" font-size="9" font-family="monospace" text-anchor="middle">${node.ip}</text>
      </g>
    `;
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" style="background-color: #0b0f19;">
  <defs>
    <radialGradient id="bgGlow" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="#1e1b4b" stop-opacity="0.5" />
      <stop offset="100%" stop-color="#0b0f19" stop-opacity="0" />
    </radialGradient>
  </defs>
  <rect width="100%" height="100%" fill="#0b0f19" />
  <circle cx="${width / 2}" cy="${height / 2}" r="${Math.min(width, height) * 0.45}" fill="url(#bgGlow)" />
  
  <text x="24" y="36" fill="#f8fafc" font-size="18" font-family="system-ui, sans-serif" font-weight="bold">${title}</text>
  <text x="24" y="56" fill="#64748b" font-size="12" font-family="monospace">Generated with NastyMap · ${graph.nodes?.length || 0} nodes · ${graph.links?.length || 0} links</text>

  <g id="links">
    ${linksSvg}
  </g>
  <g id="nodes">
    ${nodesSvg}
  </g>
</svg>`;
}

/**
 * Generate a standalone, self-contained HTML report with interactive styling, SVG topology, and host table.
 * @param {Object} scan Structured NmapRun object
 * @param {Object} graph TopologyGraph
 * @returns {string} Standalone HTML document
 */
export function generateHtmlReport(scan, graph) {
  const svgContent = generateHeadlessSvg(graph, {
    title: `Nmap Scan Topology: ${scan.args || scan.target || 'Network Scan'}`
  });

  const hostsList = (scan.hosts || [])
    .map((h) => {
      const isUp = h.status?.state === 'up' || h.isUp;
      const statusBadge = isUp
        ? '<span style="display:inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold; background: #065f46; color: #34d399;">UP</span>'
        : '<span style="display:inline-block; padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: bold; background: #881337; color: #f87171;">DOWN</span>';

      const openPorts = (h.ports || [])
        .filter((p) => p.state === 'open')
        .map((p) => {
          const sName = p.service?.product
            ? ` (${p.service.product}${p.service.version ? ' ' + p.service.version : ''})`
            : p.service?.name
              ? ` (${p.service.name})`
              : '';
          return `${p.portid || p.port}/${p.protocol}${sName}`;
        })
        .join(', ');

      const vulnBadge = h.vulnerabilitiesCount && h.vulnerabilitiesCount > 0
        ? `<span style="color:#ef4444; font-weight:bold;">⚠️ ${h.vulnerabilitiesCount} CVE/Vuln</span>`
        : '<span style="color:#64748b;">-</span>';

      return `
      <tr style="border-bottom: 1px solid #1e293b;">
        <td style="padding: 10px 14px; font-family: monospace; color: #38bdf8; font-weight: bold;">${h.ipv4 || h.id}</td>
        <td style="padding: 10px 14px; color: #f8fafc;">${h.primaryHostname || '-'}</td>
        <td style="padding: 10px 14px;">${statusBadge}</td>
        <td style="padding: 10px 14px; color: #94a3b8;">${h.primaryOs || h.osFamily || 'Unknown'}</td>
        <td style="padding: 10px 14px; color: #cbd5e1; font-family: monospace;">${openPorts || '<span style="color:#64748b;">None</span>'}</td>
        <td style="padding: 10px 14px;">${vulnBadge}</td>
        <td style="padding: 10px 14px; color: #94a3b8;">${h.latencyMs !== undefined ? `${h.latencyMs} ms` : '-'}</td>
      </tr>
      `;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NastyMap - Security Topology & Network Scan Report</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --border: #1e293b;
      --primary: #38bdf8;
      --accent: #818cf8;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    body {
      margin: 0;
      padding: 28px;
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
    }
    .container {
      max-width: 1280px;
      margin: 0 auto;
    }
    .header {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .stat-val {
      font-size: 24px;
      font-weight: bold;
      color: var(--primary);
    }
    .stat-label {
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .map-container {
      margin: 24px 0;
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      background: #030712;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .map-container svg {
      width: 100%;
      height: auto;
      display: block;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th {
      background: #1e293b;
      padding: 12px 14px;
      color: var(--muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
    }
    .table-container {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--card-bg);
    }
    .footer {
      margin-top: 32px;
      text-align: center;
      color: #64748b;
      font-size: 12px;
      border-top: 1px solid var(--border);
      padding-top: 16px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1 style="margin: 0 0 6px 0; font-size: 26px; color: var(--primary);">🛡️ NastyMap Security Topology Report</h1>
        <p style="margin: 0; color: var(--muted); font-family: monospace; font-size: 13px;">Command: ${scan.args || scan.target || 'Nmap Network Scan'}</p>
        <p style="margin: 4px 0 0 0; color: #64748b; font-size: 12px;">Scanned: ${scan.startstr || new Date().toISOString()} · Nmap v${scan.version || '7.x'} · File: ${scan.filename || 'active'}</p>
      </div>
      <div style="text-align: right;">
        <span style="display:inline-block; padding: 4px 12px; border-radius: 9999px; background: #1e1b4b; color: #a5b4fc; font-size: 12px; font-weight: bold; border: 1px solid #3730a3;">
          Vigilante + NastyMap Engine
        </span>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val">${scan.hosts?.length || 0}</div>
        <div class="stat-label">Total Hosts Discovered</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #22c55e;">${scan.hosts?.filter(h => h.isUp || h.status?.state === 'up').length || 0}</div>
        <div class="stat-label">Live Hosts (Up)</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #f59e0b;">${(scan.hosts || []).reduce((acc, h) => acc + (h.openPortsCount || 0), 0)}</div>
        <div class="stat-label">Open Network Ports</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color: #ec4899;">${graph.subnets?.length || 1}</div>
        <div class="stat-label">Subnets Mapped</div>
      </div>
    </div>

    <h2 style="font-size: 18px; color: #f8fafc; margin: 28px 0 12px 0;">🌐 Interactive Network Topology</h2>
    <div class="map-container">
      ${svgContent}
    </div>

    <h2 style="font-size: 18px; color: #f8fafc; margin: 28px 0 12px 0;">📋 Discovered Hosts & Service Fingerprints</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>Status</th>
            <th>Operating System</th>
            <th>Open Ports & Services</th>
            <th>Vulnerabilities</th>
            <th>Latency</th>
          </tr>
        </thead>
        <tbody>
          ${hostsList}
        </tbody>
      </table>
    </div>

    <div class="footer">
      Generated automatically by <strong>Vigilante Cyber Security Platform</strong> with <strong>NastyMap Engine</strong>.
    </div>
  </div>
</body>
</html>`;
}
