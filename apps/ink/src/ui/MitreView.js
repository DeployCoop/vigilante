/**
 * VIGILANTE Interactive MITRE ATT&CK Matrix & Coverage Gap Explorer View
 * React Ink terminal dashboard visualizing enterprise tactics, covered vs gap techniques,
 * and security posture scores using ANSI terminal canvas grids.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput, useApp } from 'ink';
import { useTheme } from './theme.js';
import { renderMitreHeatmapGrid } from './canvas.js';
import { generateMitreCoverageMatrix } from '../engine/mitre.js';

export function MitreView({ onReturn = null }) {
  const theme = useTheme();
  const { exit } = useApp();
  const [coverageData, setCoverageData] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadMatrix = useCallback(() => {
    try {
      setLoading(true);
      const matrix = generateMitreCoverageMatrix([], []);
      setCoverageData(matrix);
    } catch {
      // Fallback
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMatrix();
  }, [loadMatrix]);

  useInput((input, key) => {
    if (key.escape || input === 'q') {
      if (typeof onReturn === 'function') {
        onReturn();
      } else {
        exit();
      }
    } else if (input === 'r') {
      loadMatrix();
    }
  });

  const renderedGrid = coverageData?.coverageMap
    ? renderMitreHeatmapGrid(coverageData.coverageMap)
    : renderMitreHeatmapGrid({});

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
        Text,
        { bold: true, color: 'cyan' },
        '🥋 MITRE ATT&CK® COVERAGE MATRIX & DEFENSIVE GAPS'
      ),
      React.createElement(
        Text,
        { color: 'yellow', bold: true },
        coverageData ? `Overall Coverage: ${coverageData.overallCoveragePercent || 100}%` : 'Loading...'
      )
    ),

    // Sub-header instructions
    React.createElement(
      Box,
      { flexDirection: 'row', justifyContent: 'space-between', paddingX: 1, marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'green', bold: true }, '[r] '),
        React.createElement(Text, { color: 'white' }, 'Recalculate Matrix  '),
        React.createElement(Text, { color: 'gray', bold: true }, '[q/Esc] '),
        React.createElement(Text, { color: 'white' }, 'Return to Hub')
      ),
      React.createElement(
        Text,
        { color: 'gray' },
        'Real-time Tactics: TA0001 (Initial Access) -> TA0040 (Impact)'
      )
    ),

    // Rendered ANSI Canvas Grid
    React.createElement(
      Box,
      {
        flexDirection: 'column',
        borderStyle: 'round',
        borderColor: theme.border || 'gray',
        padding: 1,
        marginBottom: 1
      },
      React.createElement(Text, null, renderedGrid)
    )
  );
}
