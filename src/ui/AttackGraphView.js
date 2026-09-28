/**
 * VIGILANTE Interactive Terminal Attack Graph & Blast-Radius Explorer View
 * React Ink terminal view enabling operators to traverse attack paths,
 * calculate blast radius from compromised assets, and inspect crown jewel exposure.
 */

import React, { useState, useMemo } from 'react';
import { Box, Text, useInput, useApp } from 'ink';
import { useTheme } from './theme.js';
import {
  buildCompositeAttackGraph,
  calculateBlastRadius,
  findShortestAttackPath
} from '../engine/attackgraph.js';

export function AttackGraphView({ onReturn = null }) {
  const theme = useTheme();
  const { exit } = useApp();

  const graph = useMemo(() => buildCompositeAttackGraph(), []);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showBlastRadius, setShowBlastRadius] = useState(true);
  const [targetCrownJewel, setTargetCrownJewel] = useState('sa-cluster-admin');
  const [showPath, setShowPath] = useState(false);

  const selectedNode = graph.nodes[selectedIndex] || graph.nodes[0];

  const blastRadius = useMemo(() => {
    if (!selectedNode) return null;
    try {
      return calculateBlastRadius(selectedNode.id, graph);
    } catch {
      return null;
    }
  }, [selectedNode, graph]);

  const shortestPath = useMemo(() => {
    if (!selectedNode || !targetCrownJewel) return null;
    return findShortestAttackPath(selectedNode.id, targetCrownJewel, graph);
  }, [selectedNode, targetCrownJewel, graph]);

  useInput((input, key) => {
    if (key.escape || input === 'q') {
      if (typeof onReturn === 'function') {
        onReturn();
      } else {
        exit();
      }
      return;
    }

    if (key.upArrow || input === 'k') {
      setSelectedIndex(idx => Math.max(0, idx - 1));
    }
    if (key.downArrow || input === 'j') {
      setSelectedIndex(idx => Math.min(graph.nodes.length - 1, idx + 1));
    }

    // Toggle Blast Radius view
    if (input === 'b' || input === 'B') {
      setShowBlastRadius(b => !b);
    }

    // Toggle Path discovery to Crown Jewel
    if (input === 'p' || input === 'P') {
      setShowPath(p => !p);
    }

    // Switch target crown jewel
    if (input === 't' || input === 'T') {
      const crownJewels = graph.nodes.filter(n => n.tier === 'CrownJewel').map(n => n.id);
      if (crownJewels.length > 0) {
        const nextIdx = (crownJewels.indexOf(targetCrownJewel) + 1) % crownJewels.length;
        setTargetCrownJewel(crownJewels[nextIdx]);
      }
    }
  });

  const getTierColor = (tier) => {
    switch (tier) {
      case 'CrownJewel': return 'red';
      case 'Restricted': return 'yellow';
      case 'Infrastructure': return 'cyan';
      case 'Edge': return 'green';
      default: return 'gray';
    }
  };

  const getGlyph = (type) => {
    switch (type) {
      case 'External': return '🌐';
      case 'Workload': return '📦';
      case 'Datastore': return '💾';
      case 'Host': return '🖥️';
      case 'Identity': return '🔑';
      case 'IdentityStore': return '👑';
      default: return '⚪';
    }
  };

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%' },

    // Header banner
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
        React.createElement(Text, { bold: true, color: 'cyan' }, '🕸️  VIGILANTE ATTACK GRAPH & BLAST RADIUS '),
        React.createElement(Text, { color: 'gray' }, '| Multi-Stage Lateral Movement & Privilege Escalation')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'yellow', bold: true }, `Nodes: ${graph.nodes.length} `),
        React.createElement(Text, { color: 'gray' }, `| Edges: ${graph.edges.length} | `),
        React.createElement(Text, { color: 'red', bold: true }, `Crown Jewels: ${graph.stats.crownJewels}`)
      )
    ),

    // Hotkey navigation
    React.createElement(
      Box,
      { flexDirection: 'row', paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: 'yellow', bold: true }, '[↑/↓ or j/k] '),
      React.createElement(Text, { color: 'white' }, 'Select Node  '),
      React.createElement(Text, { color: 'magenta', bold: true }, '[b] '),
      React.createElement(Text, { color: 'white' }, `Toggle Blast Radius (${showBlastRadius ? 'ON' : 'OFF'})  `),
      React.createElement(Text, { color: 'cyan', bold: true }, '[p] '),
      React.createElement(Text, { color: 'white' }, `Trace Path to Crown Jewel (${showPath ? 'ON' : 'OFF'})  `),
      React.createElement(Text, { color: 'yellow', bold: true }, '[t] '),
      React.createElement(Text, { color: 'white' }, `Target: ${targetCrownJewel}  `),
      React.createElement(Text, { color: 'gray', bold: true }, '[q/Esc] '),
      React.createElement(Text, { color: 'white' }, 'Exit')
    ),

    // Split Layout
    React.createElement(
      Box,
      { flexDirection: 'row', width: '100%' },

      // Left Column: Node Catalog
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '45%',
          borderStyle: 'round',
          borderColor: 'cyan',
          padding: 1,
          marginRight: 1
        },
        React.createElement(
          Box,
          { marginBottom: 1 },
          React.createElement(Text, { bold: true, color: 'cyan', underline: true }, '🏰 Topology Assets & Identities')
        ),
        graph.nodes.map((node, idx) => {
          const isSelected = idx === selectedIndex;
          const isCrown = node.tier === 'CrownJewel';
          return React.createElement(
            Box,
            { key: node.id, flexDirection: 'row', justifyContent: 'space-between', marginBottom: 0 },
            React.createElement(
              Box,
              null,
              React.createElement(Text, { color: isSelected ? 'cyan' : 'white', bold: isSelected }, isSelected ? '▶ ' : '  '),
              React.createElement(Text, null, `${getGlyph(node.type)} `),
              React.createElement(Text, { bold: isSelected, color: isSelected ? 'white' : 'gray' }, node.label)
            ),
            React.createElement(
              Text,
              { color: getTierColor(node.tier), bold: isCrown },
              `[${node.tier}]`
            )
          );
        })
      ),

      // Right Column: Asset Details & Blast Radius / Paths
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '55%',
          borderStyle: 'round',
          borderColor: blastRadius?.riskLevel === 'CRITICAL' ? 'red' : 'gray',
          padding: 1
        },
        React.createElement(
          Box,
          { justifyContent: 'space-between', marginBottom: 1 },
          React.createElement(
            Text,
            { bold: true, color: getTierColor(selectedNode.tier) },
            `🎯 Selected: ${selectedNode.label}`
          ),
          React.createElement(
            Text,
            { color: 'gray' },
            `ID: ${selectedNode.id}`
          )
        ),
        React.createElement(Text, { color: 'white', dimColor: true }, selectedNode.details || 'No extended metadata'),
        React.createElement(Box, { marginY: 1, borderStyle: 'single', borderColor: 'gray' }),

        // Blast Radius section
        showBlastRadius && blastRadius
          ? React.createElement(
              Box,
              { flexDirection: 'column' },
              React.createElement(
                Box,
                { justifyContent: 'space-between', marginBottom: 1 },
                React.createElement(Text, { bold: true, color: 'magenta' }, '💥 Blast Radius Impact Analysis:'),
                React.createElement(
                  Text,
                  {
                    bold: true,
                    color: blastRadius.riskLevel === 'CRITICAL' ? 'red' : blastRadius.riskLevel === 'HIGH' ? 'yellow' : 'green'
                  },
                  `Score: ${blastRadius.impactScore}/100 [${blastRadius.riskLevel}]`
                )
              ),
              React.createElement(
                Text,
                { color: 'white' },
                `Reachable Downstream Assets: ${blastRadius.reachableCount} / ${graph.nodes.length - 1}`
              ),
              React.createElement(
                Box,
                { flexDirection: 'column', marginTop: 1 },
                blastRadius.reachableNodes.slice(0, 5).map((rn) =>
                  React.createElement(
                    Text,
                    { key: rn.id, color: getTierColor(rn.tier), marginLeft: 2 },
                    `• Hop +${rn.depth}: ${rn.label} (${rn.type}) via ${rn.viaEdge?.type}`
                  )
                )
              )
            )
          : null,

        // Path trace section
        showPath && shortestPath
          ? React.createElement(
              Box,
              { flexDirection: 'column', marginTop: 1 },
              React.createElement(
                Text,
                { bold: true, color: 'cyan' },
                `🚩 Shortest Path to Crown Jewel [${targetCrownJewel}]:`
              ),
              shortestPath.pathFound
                ? React.createElement(
                    Box,
                    { flexDirection: 'column', marginTop: 1 },
                    React.createElement(
                      Text,
                      { color: 'yellow', bold: true },
                      `Total Hops: ${shortestPath.hops} (Chain: ${shortestPath.nodePath.join(' ➔ ')})`
                    ),
                    shortestPath.edgePath.map((e, i) =>
                      React.createElement(
                        Text,
                        { key: i, color: 'magenta', marginLeft: 2 },
                        `Step ${i + 1}: ${e.from} ──[ ${e.label} ]──▶ ${e.to}`
                      )
                    )
                  )
                : React.createElement(
                    Text,
                    { color: 'green', bold: true, marginTop: 1 },
                    `✔ No viable pivot path from ${selectedNode.id} to ${targetCrownJewel} (Air-gapped)`
                  )
            )
          : null
      )
    )
  );
}
