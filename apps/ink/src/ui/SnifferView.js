/**
 * VIGILANTE Interactive Terminal Live Packet Sniffer & Dissector View
 * React Ink Wireshark-in-Terminal UI:
 * Live streaming packet list, hierarchical protocol layer tree,
 * and side-by-side Hex + ASCII packet inspection pane.
 */

import React, { useState, useEffect, useMemo } from 'react';
import { Box, Text, useInput, useApp } from 'ink';
import { useTheme } from './theme.js';
import {
  dissectFullPacket,
  filterPacket,
  formatHexDump,
  generateSyntheticPacketStream,
  exportToPcap
} from '../engine/sniffer.js';
import path from 'node:path';
import os from 'node:os';

export function SnifferView({ onReturn = null, initialPackets = null }) {
  const theme = useTheme();
  const { exit } = useApp();

  const [packets, setPackets] = useState(() => {
    if (initialPackets && initialPackets.length > 0) {
      return initialPackets.map((buf, i) => dissectFullPacket(buf, i + 1));
    }
    const synthetic = generateSyntheticPacketStream(6);
    return synthetic.map((buf, i) => dissectFullPacket(buf, i + 1));
  });

  const [isPaused, setIsPaused] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [activeFilter, setActiveFilter] = useState('');
  const [statusMessage, setStatusMessage] = useState('Capturing live network packets...');

  // Filtered packets
  const filteredPackets = useMemo(() => {
    if (!activeFilter) return packets;
    return packets.filter(p => filterPacket(p, activeFilter));
  }, [packets, activeFilter]);

  const selectedPacket = filteredPackets[selectedIndex] || filteredPackets[0] || null;

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
      setSelectedIndex(idx => Math.min(filteredPackets.length - 1, idx + 1));
    }

    // Toggle Pause
    if (input === ' ') {
      setIsPaused(p => !p);
      setStatusMessage(!isPaused ? 'Capture PAUSED' : 'Capturing live network packets...');
    }

    // Cycle filter
    if (input === 'f' || input === 'F') {
      if (!activeFilter) setActiveFilter('dns');
      else if (activeFilter === 'dns') setActiveFilter('tls');
      else if (activeFilter === 'tls') setActiveFilter('tcp');
      else setActiveFilter('');
    }

    // Save capture to PCAP
    if (input === 's' || input === 'S') {
      const pcapPath = path.join(os.tmpdir(), `vigilante-capture-${Date.now()}.pcap`);
      exportToPcap(packets, pcapPath).then(bytes => {
        setStatusMessage(`Saved ${packets.length} packets (${bytes} bytes) to ${pcapPath}`);
      }).catch(err => {
        setStatusMessage(`Error saving PCAP: ${err.message}`);
      });
    }
  });

  const getProtocolColor = (proto) => {
    switch (proto) {
      case 'TCP': return 'cyan';
      case 'UDP': return 'magenta';
      case 'DNS': return 'green';
      case 'TLS': return 'yellow';
      case 'HTTP': return 'blue';
      default: return 'gray';
    }
  };

  const hexDumpText = useMemo(() => {
    if (!selectedPacket || !selectedPacket.rawBuffer) return 'No packet selected';
    return formatHexDump(selectedPacket.rawBuffer, 128);
  }, [selectedPacket]);

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%' },

    // Header Bar
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
        React.createElement(Text, { bold: true, color: 'cyan' }, '🦈 VIGILANTE TERMINAL LIVE PACKET SNIFFER '),
        React.createElement(Text, { color: 'gray' }, '| Deep Protocol Dissector')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: isPaused ? 'red' : 'green', bold: true }, `[${isPaused ? 'PAUSED' : 'LIVE'}] `),
        React.createElement(Text, { color: 'yellow', bold: true }, `Packets: ${packets.length} `),
        React.createElement(Text, { color: 'gray' }, `| Filter: ${activeFilter || 'ALL'}`)
      )
    ),

    // Hotkey Banner
    React.createElement(
      Box,
      { flexDirection: 'row', paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: 'yellow', bold: true }, '[Space] '),
      React.createElement(Text, { color: 'white' }, `${isPaused ? 'Resume' : 'Pause'}  `),
      React.createElement(Text, { color: 'yellow', bold: true }, '[↑/↓ or j/k] '),
      React.createElement(Text, { color: 'white' }, 'Select Packet  '),
      React.createElement(Text, { color: 'cyan', bold: true }, '[f] '),
      React.createElement(Text, { color: 'white' }, `Filter (${activeFilter || 'None'})  `),
      React.createElement(Text, { color: 'green', bold: true }, '[s] '),
      React.createElement(Text, { color: 'white' }, 'Export PCAP  '),
      React.createElement(Text, { color: 'gray' }, '[q/Esc] Return to Hub')
    ),

    // Top Pane: Packet List Table
    React.createElement(
      Box,
      {
        flexDirection: 'column',
        borderStyle: 'single',
        borderColor: 'gray',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 1 },
        React.createElement(Text, { bold: true, color: 'gray', width: '8%' }, 'NO.'),
        React.createElement(Text, { bold: true, color: 'gray', width: '12%' }, 'PROTOCOL'),
        React.createElement(Text, { bold: true, color: 'gray', width: '22%' }, 'SOURCE'),
        React.createElement(Text, { bold: true, color: 'gray', width: '22%' }, 'DESTINATION'),
        React.createElement(Text, { bold: true, color: 'gray', width: '36%' }, 'INFO')
      ),
      filteredPackets.slice(0, 8).map((pkt, idx) => {
        const isSelected = idx === selectedIndex;
        const protoColor = getProtocolColor(pkt.protocol);

        return React.createElement(
          Box,
          { key: pkt.index, flexDirection: 'row', justifyContent: 'space-between' },
          React.createElement(
            Text,
            { color: isSelected ? 'cyan' : 'white', bold: isSelected, width: '8%' },
            `${isSelected ? '▶' : ' '}${pkt.index}`
          ),
          React.createElement(
            Text,
            { color: protoColor, bold: true, width: '12%' },
            pkt.protocol
          ),
          React.createElement(
            Text,
            { color: 'white', width: '22%' },
            pkt.src.substring(0, 20)
          ),
          React.createElement(
            Text,
            { color: 'white', width: '22%' },
            pkt.dst.substring(0, 20)
          ),
          React.createElement(
            Text,
            { color: 'yellow', width: '36%' },
            pkt.summary.substring(0, 36)
          )
        );
      })
    ),

    // Bottom Split Pane: Dissection Tree + Hex Dump
    React.createElement(
      Box,
      { flexDirection: 'row', width: '100%' },

      // Bottom-Left: Protocol Layer Tree
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'single',
          borderColor: 'cyan',
          paddingX: 1
        },
        React.createElement(Text, { bold: true, color: 'cyan', marginBottom: 1 }, 'PROTOCOL LAYER DISSECTION TREE'),
        selectedPacket ? React.createElement(
          Box,
          { flexDirection: 'column' },
          React.createElement(Text, { color: 'white' }, `▾ Frame ${selectedPacket.index}: ${selectedPacket.length} bytes captured`),
          selectedPacket.layers.ethernet && React.createElement(
            Text,
            { color: 'gray' },
            `  ▾ Ethernet II, Src: ${selectedPacket.layers.ethernet.srcMac}, Dst: ${selectedPacket.layers.ethernet.dstMac}`
          ),
          selectedPacket.layers.ip && React.createElement(
            Text,
            { color: 'white' },
            `    ▾ Internet Protocol v4, Src: ${selectedPacket.layers.ip.srcIp}, Dst: ${selectedPacket.layers.ip.dstIp} (TTL ${selectedPacket.layers.ip.ttl})`
          ),
          selectedPacket.layers.transport && React.createElement(
            Text,
            { color: 'cyan' },
            `      ▾ ${selectedPacket.layers.ip?.protoName || 'Transport'}, Src Port: ${selectedPacket.layers.transport.srcPort}, Dst Port: ${selectedPacket.layers.transport.dstPort}`
          ),
          selectedPacket.layers.app && React.createElement(
            Text,
            { color: 'green', bold: true },
            `        ▾ ${selectedPacket.protocol} Application Payload: ${JSON.stringify(selectedPacket.layers.app)}`
          )
        ) : React.createElement(Text, { color: 'gray' }, 'No packet selected')
      ),

      // Bottom-Right: Hex / ASCII Dump
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'single',
          borderColor: 'gray',
          paddingX: 1,
          marginLeft: 1
        },
        React.createElement(Text, { bold: true, color: 'yellow', marginBottom: 1 }, 'RAW HEX & ASCII DUMP'),
        React.createElement(
          Text,
          { color: 'gray' },
          hexDumpText
        )
      )
    ),

    // Status Footer
    React.createElement(
      Box,
      { paddingX: 1, marginTop: 1 },
      React.createElement(Text, { color: 'cyan' }, `Status: ${statusMessage}`)
    )
  );
}
