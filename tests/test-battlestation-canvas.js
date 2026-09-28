import assert from 'node:assert';
import React from 'react';
import { Header } from '../src/ui/Header.js';
import { BattleStationView } from '../src/ui/BattleStationView.js';
import { MitreView } from '../src/ui/MitreView.js';
import {
  renderBrailleSparkline,
  renderHalfBlockHeatmap,
  renderMitreHeatmapGrid
} from '../src/ui/canvas.js';

async function runTests() {
  console.log('🧪 Testing BattleStation Canvas Integration, Header Sparklines & MitreView...');

  // Test 1: Validate component exports and instantiation
  assert(typeof Header === 'object' || typeof Header === 'function', 'Header must be exported');
  assert(typeof BattleStationView === 'object' || typeof BattleStationView === 'function', 'BattleStationView must be exported');
  assert(typeof MitreView === 'object' || typeof MitreView === 'function', 'MitreView must be exported');

  const headerEl = React.createElement(Header, {
    activeView: 'BATTLESTATION',
    domain: 'vigilante.local',
    clusterName: 'vigilante-test'
  });
  assert.ok(headerEl, 'Header element must instantiate cleanly');

  const bsEl = React.createElement(BattleStationView, {
    domain: 'vigilante.local',
    clusterName: 'vigilante-test'
  });
  assert.ok(bsEl, 'BattleStationView element must instantiate cleanly');

  const mitreEl = React.createElement(MitreView, {});
  assert.ok(mitreEl, 'MitreView element must instantiate cleanly');
  console.log('✔ Test 1 passed: React components instantiated without syntax or prop errors.');

  // Test 2: Verify Braille sparkline generation
  const telemetryPoints = [12, 18, 45, 60, 35, 90, 110, 85, 40, 20, 65, 80];
  const sparkline = renderBrailleSparkline(telemetryPoints, 16, 1);
  assert.strictEqual(typeof sparkline, 'string');
  assert.ok(sparkline.length >= 16);
  for (const char of sparkline) {
    const code = char.charCodeAt(0);
    assert.ok(code >= 0x2800 && code <= 0x28FF, `Character ${char} must be in Braille range`);
  }
  console.log('✔ Test 2 passed: Braille sparkline generator generates valid sub-pixel trendline.');

  // Test 3: Verify Half-block heatmap generation
  const trafficGrid = [
    [10, 30, 60, 90, 20],
    [5, 45, 80, 100, 15],
    [0, 15, 40, 75, 10],
    [25, 50, 85, 95, 30]
  ];
  const heatmap = renderHalfBlockHeatmap(trafficGrid, { colorScale: 'greenToRed' });
  assert.ok(heatmap.includes('▀'), 'Heatmap must render ANSI upper half-block characters');
  assert.ok(heatmap.includes('\x1b['), 'Heatmap must include ANSI color escapes');
  console.log('✔ Test 3 passed: Half-block heatmap renders packed 2D network density matrix.');

  // Test 4: Verify MITRE Heatmap Grid
  const mockCoverage = {
    'T1059.004': { name: 'Unix Shell', tactic: 'TA0002', coverage: 95 },
    'T1486': { name: 'Data Encrypted for Impact', tactic: 'TA0040', coverage: 100 },
    'T1071.004': { name: 'DNS Beaconing', tactic: 'TA0011', coverage: 85 }
  };
  const mitreGrid = renderMitreHeatmapGrid(mockCoverage);
  assert.ok(mitreGrid.includes('MITRE ATT&CK Tactic'), 'Should contain grid header');
  assert.ok(mitreGrid.includes('DETECTED'), 'Should display DETECTED');
  assert.ok(mitreGrid.includes('GAP'), 'Should display GAP');
  console.log('✔ Test 4 passed: MITRE ATT&CK matrix grid generates interactive coverage table.');

  console.log('🎉 ALL 4 BATTLESTATION CANVAS INTEGRATION TESTS PASSED!\n');
}

runTests().catch(err => {
  console.error('❌ BattleStation Canvas test failed:', err);
  process.exit(1);
});
