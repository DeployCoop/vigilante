import React, { useEffect } from 'react';
import { Box, Text } from 'ink';
import { useClipboard } from './ClipboardManager.js';

export const StatusDashboard = ({
  prereqs,
  cluster,
  certs,
  hosts,
  modules = [],
  domain = 'vigilante.local'
}) => {
  const { registerPanes } = useClipboard();

  useEffect(() => {
    let currentRow = 6;
    const dashboardPanes = [];

    // Pane 1: Prerequisites
    if (prereqs) {
      const prereqsHeight = 2 + (prereqs.tools?.length || 0);
      dashboardPanes.push({
        id: 'prereqs',
        title: 'Core Tooling Prerequisites',
        startRow: currentRow,
        endRow: currentRow + prereqsHeight - 1,
        getText: () => {
          return (prereqs.tools || []).map(t => `${t.name}: ${t.ready ? t.version : 'Not Available'}`).join('\n');
        }
      });
      currentRow += prereqsHeight;
    }

    // Pane 2: K3d Cluster
    if (cluster) {
      const clusterHeight = 2 + (cluster.nodes?.length || 0);
      dashboardPanes.push({
        id: 'cluster',
        title: 'Kubernetes Cluster (k3d)',
        startRow: currentRow,
        endRow: currentRow + clusterHeight - 1,
        getText: () => {
          const lines = [`Cluster: ${cluster.clusterName || 'None'} (${cluster.serversRunning}/${cluster.serversCount} servers, ${cluster.agentsRunning}/${cluster.agentsCount} agents)`];
          if (cluster.nodes) {
            for (const n of cluster.nodes) {
              lines.push(`• Node ${n.name}: ${n.status} (${n.roles.join(', ') || 'worker'})`);
            }
          }
          return lines.join('\n');
        }
      });
      currentRow += clusterHeight;
    }

    // Pane 3: TLS Certs
    if (certs) {
      const certsHeight = 2;
      dashboardPanes.push({
        id: 'certs',
        title: 'Local TLS Certificates',
        startRow: currentRow,
        endRow: currentRow + certsHeight - 1,
        getText: () => `Domain Certs: ${domain}, *.${domain} (${certs.certPath})`
      });
      currentRow += certsHeight;
    }

    // Pane 4: Local DNS (/etc/hosts)
    if (hosts) {
      const hostsHeight = 2;
      dashboardPanes.push({
        id: 'hosts',
        title: 'Local DNS (/etc/hosts)',
        startRow: currentRow,
        endRow: currentRow + hostsHeight - 1,
        getText: () => {
          return (hosts.allRequiredHosts || []).map(h => `${hosts.ip || '127.0.0.1'} ${h}`).join('\n');
        }
      });
      currentRow += hostsHeight;
    }

    // Pane 5: Modular Security Packages
    const modulesHeight = 2 + (modules.length > 0 ? modules.reduce((acc, m) => acc + 1 + (m.pods?.length || 0), 0) : 1);
    dashboardPanes.push({
      id: 'modules',
      title: 'Modular Security Packages',
      startRow: currentRow,
      endRow: currentRow + modulesHeight - 1,
      getText: () => {
        return modules.map(m => {
          const podLines = (m.pods || []).map(p => `  • Pod ${p.name}: ${p.phase} (Ready: ${p.ready ? 'Yes' : 'No'}, Restarts: ${p.restarts})`);
          return `${m.name}: ${m.status}${podLines.length > 0 ? '\n' + podLines.join('\n') : ''}`;
        }).join('\n\n');
      }
    });
    currentRow += modulesHeight;

    // Pane 6: Ingress & Service Endpoints
    const endpointsHeight = 6;
    dashboardPanes.push({
      id: 'endpoints',
      title: 'SIEM Dashboard & Credentials',
      startRow: currentRow,
      endRow: currentRow + endpointsHeight - 1,
      getText: () => `SIEM Dashboard: https://siem.${domain}\nCredentials: admin / Admin123456! (or admin / admin)`
    });

    registerPanes(dashboardPanes);
  }, [prereqs, cluster, certs, hosts, modules, domain, registerPanes]);
  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: 'green' },
    
    // Header
    React.createElement(
      Box,
      { marginBottom: 1, justifyContent: 'space-between' },
      React.createElement(
        Text,
        { bold: true, color: 'green' },
        '🛡️  VIGILANTE ENVIRONMENT STATUS'
      ),
      React.createElement(
        Text,
        { color: 'gray' },
        `Domain: ${domain}`
      )
    ),

    // 1. Prerequisites Section
    prereqs
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginBottom: 1 },
          React.createElement(Text, { bold: true, color: 'yellow' }, '1. Core Tooling Prereqs:'),
          prereqs.tools.map((t) =>
            React.createElement(
              Box,
              { key: t.id, marginLeft: 2 },
              React.createElement(
                Text,
                { color: t.ready ? 'green' : 'red', bold: true },
                t.ready ? '✔ ' : '✖ '
              ),
              React.createElement(Text, { bold: true }, `${t.name}: `),
              React.createElement(
                Text,
                { color: t.ready ? 'cyan' : 'red' },
                t.ready ? t.version : t.error || 'Not Available'
              )
            )
          )
        )
      : null,

    // 2. K3d Cluster Section
    cluster
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginBottom: 1 },
          React.createElement(Text, { bold: true, color: 'yellow' }, '2. Kubernetes Cluster (k3d):'),
          React.createElement(
            Box,
            { marginLeft: 2 },
            React.createElement(
              Text,
              { color: cluster.exists ? 'green' : 'red', bold: true },
              cluster.exists ? '✔ ' : '✖ '
            ),
            React.createElement(Text, { bold: true }, `Cluster Name: `),
            React.createElement(Text, { color: 'cyan' }, cluster.clusterName || 'None'),
            React.createElement(
              Text,
              { color: 'gray' },
              cluster.exists
                ? ` (${cluster.serversRunning}/${cluster.serversCount} servers, ${cluster.agentsRunning}/${cluster.agentsCount} agents)`
                : ' (Not Created)'
            )
          ),
          cluster.nodes && cluster.nodes.length > 0
            ? React.createElement(
                Box,
                { marginLeft: 4, flexDirection: 'column' },
                cluster.nodes.map((node, i) =>
                  React.createElement(
                    Text,
                    { key: i, color: 'gray' },
                    `• Node ${node.name}: ${node.status} (${node.roles.join(', ') || 'worker'})`
                  )
                )
              )
            : null
        )
      : null,

    // 3. Certificates Section
    certs
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginBottom: 1 },
          React.createElement(Text, { bold: true, color: 'yellow' }, '3. Local TLS (mkcert):'),
          React.createElement(
            Box,
            { marginLeft: 2 },
            React.createElement(
              Text,
              { color: certs.exists ? 'green' : 'yellow', bold: true },
              certs.exists ? '✔ ' : '○ '
            ),
            React.createElement(Text, { bold: true }, `Domain Certs: `),
            React.createElement(Text, { color: 'cyan' }, `${domain}, *.${domain}`),
            React.createElement(
              Text,
              { color: 'gray' },
              certs.exists ? ` (${certs.certPath})` : ' (Not Generated)'
            )
          )
        )
      : null,

    // 4. Local DNS (/etc/hosts) Section
    hosts
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginBottom: 1 },
          React.createElement(Text, { bold: true, color: 'yellow' }, '4. Local DNS (/etc/hosts):'),
          React.createElement(
            Box,
            { marginLeft: 2 },
            React.createElement(
              Text,
              { color: hosts.configured ? 'green' : 'yellow', bold: true },
              hosts.configured ? '✔ ' : '○ '
            ),
            React.createElement(Text, { bold: true }, `Host Mappings: `),
            React.createElement(Text, { color: 'cyan' }, `${hosts.ip} ${(hosts.allRequiredHosts || []).join(', ')}`),
            React.createElement(
              Text,
              { color: 'gray' },
              hosts.configured
                ? ` (${hosts.hasManagedBlock ? 'Managed block' : 'Configured in /etc/hosts'})`
                : ` (Missing: ${(hosts.missingHosts || []).join(', ')} - run 'vigilante hostr')`
            )
          )
        )
      : null,

    // 5. Deployed Security Modules
    React.createElement(
      Box,
      { flexDirection: 'column', marginBottom: 1 },
      React.createElement(Text, { bold: true, color: 'yellow' }, '5. Modular Security Packages:'),
      modules.length > 0
        ? modules.map((mod) =>
            React.createElement(
              Box,
              { key: mod.id, flexDirection: 'column', marginLeft: 2 },
              React.createElement(
                Box,
                null,
                React.createElement(
                  Text,
                  { color: mod.installed ? 'green' : 'gray', bold: true },
                  mod.installed ? '✔ ' : '○ '
                ),
                React.createElement(Text, { bold: true }, `${mod.name}: `),
                React.createElement(
                  Text,
                  { color: mod.status === 'Ready' ? 'green' : 'yellow' },
                  mod.status
                )
              ),
              mod.pods && mod.pods.length > 0
                ? React.createElement(
                    Box,
                    { marginLeft: 4, flexDirection: 'column' },
                    mod.pods.map((p, pi) =>
                      React.createElement(
                        Text,
                        { key: pi, color: 'gray' },
                        `• Pod ${p.name}: ${p.phase} (Ready: ${p.ready ? 'Yes' : 'No'}, Restarts: ${p.restarts})`
                      )
                    )
                  )
                : null
            )
          )
        : React.createElement(
            Box,
            { marginLeft: 2 },
            React.createElement(Text, { color: 'gray' }, 'No security modules deployed yet.')
          )
    ),

    // 6. Accessible Endpoints & SIEM Web UI
    React.createElement(
      Box,
      { flexDirection: 'column', borderStyle: 'single', borderColor: 'cyan', padding: 1, marginY: 1 },
      React.createElement(
        Text,
        { bold: true, color: 'cyan' },
        '🌐 Ingress & Service Endpoints:'
      ),
      React.createElement(
        Box,
        { flexDirection: 'column', marginTop: 0 },
        React.createElement(
          Text,
          null,
          '• SIEM Dashboard: ',
          React.createElement(Text, { color: 'cyan', bold: true, underline: true }, `https://siem.${domain}`)
        ),
        React.createElement(
          Text,
          { color: 'gray', marginLeft: 2 },
          '  OpenSearch SIEM & Security Analytics interface'
        ),
        React.createElement(
          Box,
          { marginLeft: 2, marginTop: 1 },
          React.createElement(Text, { color: 'yellow', bold: true }, '🔑 Credentials: '),
          React.createElement(Text, { color: 'white', bold: true }, 'admin'),
          React.createElement(Text, { color: 'gray' }, ' / '),
          React.createElement(Text, { color: 'white', bold: true }, 'Admin123456!'),
          React.createElement(Text, { color: 'gray' }, ' (or '),
          React.createElement(Text, { color: 'white' }, 'admin'),
          React.createElement(Text, { color: 'gray' }, ' / '),
          React.createElement(Text, { color: 'white' }, 'admin'),
          React.createElement(Text, { color: 'gray' }, ')')
        ),
        React.createElement(
          Box,
          { marginTop: 1 },
          React.createElement(
            Text,
            { color: hosts && hosts.configured ? 'green' : 'yellow' },
            hosts && hosts.configured
              ? `✔ Local DNS mapped: ${hosts.ip} siem.${domain}`
              : `💡 Note: Run 'vigilante hostr' or ensure /etc/hosts includes: 127.0.0.1 siem.${domain}`
          )
        ),
        React.createElement(
          Box,
          { marginTop: 1, flexDirection: 'row', justifyContent: 'space-between' },
          React.createElement(
            Text,
            { color: 'cyan', bold: true },
            '⚡ Press [p] for Live Pod Monitor (-A -o wide)'
          ),
          React.createElement(
            Text,
            { color: 'magenta', bold: true },
            '⚡ Press [t] for Threat Simulation'
          )
        )
      )
    )
  );
};
