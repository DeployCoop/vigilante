/**
 * VIGILANTE Terminal Braille Heatmaps & ANSI Canvas Visualizations
 * Provides high-resolution Unicode Braille sparklines, ANSI half-block heatmaps,
 * and MITRE ATT&CK terminal coverage grids.
 */

// Braille dot bitmask mapping:
// col 0: row 0=0x01, row 1=0x02, row 2=0x04, row 3=0x40
// col 1: row 0=0x08, row 1=0x10, row 2=0x20, row 3=0x80
const BRAILLE_DOTS = [
  [0x01, 0x08], // y = 3 (bottom) or y = 0 (top)
  [0x02, 0x10],
  [0x04, 0x20],
  [0x40, 0x80]
];

/**
 * Render high-resolution 2x4 sub-pixel sparkline using Unicode Braille characters (\u2800 - \u28FF).
 * @param {Array<number>} dataPoints - Sequence of numbers to plot
 * @param {number} width - Number of characters in terminal width (each char has 2 sub-columns)
 * @param {number} height - Number of lines in terminal height (each line has 4 sub-rows)
 * @returns {string} Multiline or single-line Braille string
 */
export function renderBrailleSparkline(dataPoints = [], width = 20, height = 1) {
  if (!dataPoints || dataPoints.length === 0) {
    return ' '.repeat(width);
  }

  const numCols = width * 2;
  const numRows = height * 4;

  // Resample dataPoints to match numCols
  const resampled = [];
  if (dataPoints.length === 1) {
    for (let c = 0; c < numCols; c++) resampled.push(dataPoints[0]);
  } else {
    for (let c = 0; c < numCols; c++) {
      const pos = (c / (numCols - 1)) * (dataPoints.length - 1);
      const low = Math.floor(pos);
      const high = Math.ceil(pos);
      const weight = pos - low;
      const val = dataPoints[low] * (1 - weight) + dataPoints[high] * weight;
      resampled.push(val);
    }
  }

  const min = Math.min(...resampled);
  const max = Math.max(...resampled);
  const range = max - min || 1;

  // Grid of boolean pixels [y][x] where y=0 is top, y=numRows-1 is bottom
  const pixels = Array.from({ length: numRows }, () => new Array(numCols).fill(false));

  for (let c = 0; c < numCols; c++) {
    const norm = (resampled[c] - min) / range; // 0.0 to 1.0
    const fillHeight = Math.max(1, Math.round(norm * (numRows - 1))); // at least 1 dot if > min or bottom dot
    const targetY = (numRows - 1) - fillHeight;

    // Fill line or filled area (sparkline fills from bottom up to targetY)
    for (let r = numRows - 1; r >= targetY; r--) {
      if (r >= 0 && r < numRows) {
        pixels[r][c] = true;
      }
    }
  }

  // Convert pixel matrix to Braille character blocks (height rows of width chars)
  const lines = [];
  for (let h = 0; h < height; h++) {
    let line = '';
    const startY = h * 4;

    for (let w = 0; w < width; w++) {
      const startX = w * 2;
      let code = 0x2800; // empty Braille character

      for (let dy = 0; dy < 4; dy++) {
        const y = startY + dy;
        for (let dx = 0; dx < 2; dx++) {
          const x = startX + dx;
          if (y < numRows && x < numCols && pixels[y][x]) {
            code |= BRAILLE_DOTS[dy][dx];
          }
        }
      }
      line += String.fromCharCode(code);
    }
    lines.push(line);
  }

  return lines.join('\n');
}

/**
 * Render half-block heatmap (▀ \u2580) where 2 vertical pixels are mapped per line.
 * @param {Array<Array<number>>} gridData - 2D matrix of numeric values (rows x cols)
 * @param {Object} options - { minVal, maxVal, colorScale }
 * @returns {string} ANSI colored terminal representation
 */
export function renderHalfBlockHeatmap(gridData = [[]], options = {}) {
  if (!gridData || gridData.length === 0 || gridData[0].length === 0) {
    return '';
  }

  const numRows = gridData.length;
  const numCols = gridData[0].length;

  let minVal = options.minVal;
  let maxVal = options.maxVal;

  if (minVal === undefined || maxVal === undefined) {
    let allVals = [];
    for (const row of gridData) allVals.push(...row);
    if (minVal === undefined) minVal = Math.min(...allVals);
    if (maxVal === undefined) maxVal = Math.max(...allVals);
  }
  const range = maxVal - minVal || 1;

  const colorScale = options.colorScale || 'greenToRed'; // 'greenToRed', 'blueToCyan', 'grayscale'

  function valueToRgb(val) {
    const norm = Math.max(0, Math.min(1, (val - minVal) / range));
    if (colorScale === 'greenToRed') {
      // 0.0 = Green (0, 220, 50), 0.5 = Yellow (220, 200, 0), 1.0 = Red (255, 30, 60)
      if (norm < 0.5) {
        const t = norm * 2;
        const r = Math.round(t * 220);
        const g = Math.round(220 - t * 20);
        return [r, g, 30];
      } else {
        const t = (norm - 0.5) * 2;
        const r = Math.round(220 + t * 35);
        const g = Math.round(200 - t * 170);
        return [r, g, 40];
      }
    } else if (colorScale === 'cyan') {
      const b = Math.round(norm * 255);
      return [0, Math.round(norm * 200), b];
    } else {
      const g = Math.round(norm * 255);
      return [g, g, g];
    }
  }

  const lines = [];

  // Group rows in pairs of 2 (top pixel = row, bottom pixel = row + 1)
  for (let r = 0; r < numRows; r += 2) {
    let line = '';
    const topRow = gridData[r];
    const bottomRow = r + 1 < numRows ? gridData[r + 1] : null;

    for (let c = 0; c < numCols; c++) {
      const topVal = topRow[c] !== undefined ? topRow[c] : minVal;
      const [tr, tg, tb] = valueToRgb(topVal);

      if (bottomRow && bottomRow[c] !== undefined) {
        const [br, bg, bb] = valueToRgb(bottomRow[c]);
        // \x1b[38;2;R;G;Bm foreground (top), \x1b[48;2;R;G;Bm background (bottom)
        line += `\x1b[38;2;${tr};${tg};${tb}m\x1b[48;2;${br};${bg};${bb}m▀\x1b[0m`;
      } else {
        line += `\x1b[38;2;${tr};${tg};${tb}m▀\x1b[0m`;
      }
    }
    lines.push(line);
  }

  return lines.join('\n');
}

/**
 * Render MITRE ATT&CK Matrix Grid with status colors
 * Green: 100% covered / detected
 * Yellow: Partial coverage
 * Red: Untested defensive gap
 * @param {Object} coverageMap - { [techniqueId]: { name, status: 'DETECTED'|'PARTIAL'|'GAP', coverage: number } }
 * @param {Array<Object>} tacticsList - Optional list of tactics
 * @returns {string} Formatted terminal grid
 */
export function renderMitreHeatmapGrid(coverageMap = {}, tacticsList = []) {
  const ANSI = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    green: '\x1b[38;2;0;255;120m',
    yellow: '\x1b[38;2;255;190;0m',
    red: '\x1b[38;2;255;60;80m',
    dim: '\x1b[2m',
    cyan: '\x1b[36m'
  };

  const defaultTactics = tacticsList.length > 0 ? tacticsList : [
    { id: 'TA0001', name: 'Initial Access' },
    { id: 'TA0002', name: 'Execution' },
    { id: 'TA0003', name: 'Persistence' },
    { id: 'TA0004', name: 'Privilege Escalation' },
    { id: 'TA0005', name: 'Defense Evasion' },
    { id: 'TA0006', name: 'Credential Access' },
    { id: 'TA0007', name: 'Discovery' },
    { id: 'TA0008', name: 'Lateral Movement' },
    { id: 'TA0009', name: 'Collection' },
    { id: 'TA0011', name: 'Command & Control' },
    { id: 'TA0010', name: 'Exfiltration' },
    { id: 'TA0040', name: 'Impact' }
  ];

  const header = `${ANSI.bold}${ANSI.cyan}┌───────────────────────┬────────────┬─────────────┬─────────────┐${ANSI.reset}\n` +
                 `${ANSI.bold}${ANSI.cyan}│ MITRE ATT&CK Tactic   │ Techniques │ Status      │ Coverage    │${ANSI.reset}\n` +
                 `${ANSI.bold}${ANSI.cyan}├───────────────────────┼────────────┼─────────────┼─────────────┤${ANSI.reset}`;

  let totalDetected = 0;
  let totalPartial = 0;
  let totalGap = 0;
  let totalItems = 0;

  const rows = defaultTactics.map(tactic => {
    // Find all matching techniques for this tactic in coverageMap
    const matches = Object.entries(coverageMap).filter(([tid, data]) => {
      return data.tactic === tactic.id || data.tacticName === tactic.name;
    });

    let statusTag = `${ANSI.red}GAP${ANSI.reset}`;
    let coveragePct = '  0%';
    let count = matches.length;

    if (count > 0) {
      const avg = matches.reduce((acc, [_, d]) => acc + (d.coverage || 0), 0) / count;
      coveragePct = `${Math.round(avg).toString().padStart(3, ' ')}%`;

      if (avg >= 85) {
        statusTag = `${ANSI.green}DETECTED${ANSI.reset}`;
        totalDetected++;
      } else if (avg > 0) {
        statusTag = `${ANSI.yellow}PARTIAL${ANSI.reset} `;
        totalPartial++;
      } else {
        totalGap++;
      }
    } else {
      totalGap++;
    }
    totalItems++;

    const tacticNamePadded = tactic.name.padEnd(21, ' ').slice(0, 21);
    const countPadded = count.toString().padStart(10, ' ');
    const coveragePadded = coveragePct.padStart(11, ' ');

    return `│ ${tacticNamePadded} │ ${countPadded} │ ${statusTag}    │ ${coveragePadded} │`;
  });

  const footer = `${ANSI.bold}${ANSI.cyan}└───────────────────────┴────────────┴─────────────┴─────────────┘${ANSI.reset}\n` +
                 `${ANSI.dim}Legend: ${ANSI.green}■ DETECTED (${totalDetected})${ANSI.reset} ${ANSI.yellow}■ PARTIAL (${totalPartial})${ANSI.reset} ${ANSI.red}■ GAP (${totalGap})${ANSI.reset}`;

  return [header, ...rows, footer].join('\n');
}
