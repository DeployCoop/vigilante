import assert from 'node:assert';
import {
  renderBrailleSparkline,
  renderHalfBlockHeatmap,
  renderMitreHeatmapGrid
} from '../src/ui/canvas.js';

console.log('🧪 Testing Terminal Braille Heatmaps & ANSI Canvas Visualizations...');

// Test 1: Braille Sparkline rendering
const trendData = [10, 25, 40, 50, 75, 90, 60, 45, 30, 85, 100];
const sparkline = renderBrailleSparkline(trendData, 12, 1);
assert.ok(sparkline, 'Sparkline string should not be empty');
assert.strictEqual(typeof sparkline, 'string');
// Check that Braille characters are in unicode range \u2800-\u28FF
for (const char of sparkline) {
  const code = char.charCodeAt(0);
  assert.ok(code >= 0x2800 && code <= 0x28FF, `Character ${char} (code ${code.toString(16)}) must be in Braille range`);
}
console.log('✔ Test 1 passed: renderBrailleSparkline produces valid Unicode Braille trendline.');

// Multi-line sparkline test
const multilineSpark = renderBrailleSparkline(trendData, 10, 3);
const lines = multilineSpark.split('\n');
assert.strictEqual(lines.length, 3, 'Should produce 3 lines for height=3');
console.log('✔ Test 1b passed: Multi-row Braille sparkline renders correct vertical dimension.');

// Test 2: Half-block heatmap rendering
const matrix = [
  [0, 20, 50, 80],
  [10, 40, 70, 100],
  [5, 15, 60, 95],
  [30, 45, 85, 90]
];
const heatmap = renderHalfBlockHeatmap(matrix, { minVal: 0, maxVal: 100, colorScale: 'greenToRed' });
assert.ok(heatmap.includes('▀'), 'Heatmap must contain upper half-block characters');
assert.ok(heatmap.includes('\x1b['), 'Heatmap must contain ANSI escape codes');
assert.strictEqual(heatmap.split('\n').length, 2, '4 matrix rows should be packed into 2 terminal half-block lines');
console.log('✔ Test 2 passed: renderHalfBlockHeatmap correctly packs 2D numeric grid into colored half-block lines.');

// Test 3: MITRE ATT&CK Matrix Grid renderer
const mockCoverage = {
  'T1059': { name: 'Command and Scripting Interpreter', tactic: 'TA0002', coverage: 100 },
  'T1059.004': { name: 'Unix Shell', tactic: 'TA0002', coverage: 90 },
  'T1078': { name: 'Valid Accounts', tactic: 'TA0001', coverage: 50 },
  'T1021': { name: 'Remote Services', tactic: 'TA0008', coverage: 100 }
};

const grid = renderMitreHeatmapGrid(mockCoverage);
assert.ok(grid.includes('MITRE ATT&CK Tactic'), 'Grid should include header');
assert.ok(grid.includes('DETECTED'), 'Grid should show DETECTED tag');
assert.ok(grid.includes('PARTIAL'), 'Grid should show PARTIAL tag');
assert.ok(grid.includes('GAP'), 'Grid should show GAP tag');
assert.ok(grid.includes('Initial Access'), 'Grid should show Initial Access tactic');
console.log('✔ Test 3 passed: renderMitreHeatmapGrid renders color-coded tactic rows and summary legend.');

console.log('🎉 All Terminal Braille Heatmaps & ANSI Canvas Visualizations tests passed successfully!\n');
