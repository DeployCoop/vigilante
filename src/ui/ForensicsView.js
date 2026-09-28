import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { listCarvedFiles } from '../engine/forensics.js';
import { useTheme } from './theme.js';

export function ForensicsView({ onBack }) {
  const theme = useTheme();
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const items = await listCarvedFiles();
        if (mounted) {
          setFiles(items);
          setLoading(false);
        }
      } catch {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => { mounted = false; };
  }, []);

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%', height: '100%', padding: 1 },
    React.createElement(
      Box,
      { borderStyle: 'round', borderColor: theme.colors.primary, paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.header, bold: true }, '🔬 Deep PCAP Forensic Extraction & Protocol Reconstruction')
    ),
    React.createElement(
      Box,
      { marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.muted }, 'Carved Payloads, Decrypted TLS Streams, and TCP Sequence Ladder Telemetry')
    ),
    loading
      ? React.createElement(Text, { color: theme.colors.accent }, 'Scanning forensic dropzone...')
      : files.length === 0
        ? React.createElement(
            Box,
            { flexDirection: 'column', padding: 1 },
            React.createElement(Text, { color: theme.colors.muted }, 'No carved payloads currently discovered.'),
            React.createElement(Text, { color: theme.colors.info }, 'Carve PCAP files with: vigilante forensics <path-to-pcap>')
          )
        : React.createElement(
            Box,
            { flexDirection: 'column', borderStyle: 'single', borderColor: theme.colors.border, padding: 1 },
            React.createElement(Text, { color: theme.colors.accent, bold: true }, `Carved Forensic Artifacts (${files.length}):`),
            files.map((f, i) =>
              React.createElement(
                Box,
                { key: i, justifyContent: 'space-between' },
                React.createElement(Text, { color: theme.colors.text }, `📦 ${f.fileName} (${f.sizeBytes} bytes)`),
                React.createElement(Text, { color: theme.colors.muted }, f.modifiedAt)
              )
            )
          ),
    React.createElement(
      Box,
      { marginTop: 1, borderStyle: 'single', borderColor: theme.colors.border, paddingX: 1 },
      React.createElement(Text, { color: theme.colors.muted }, '[Esc/q] Back to Hub  |  [r] Rescan Dropzone  |  [c] Carve Active PCAP')
    )
  );
}
