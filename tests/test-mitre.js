import assert from 'node:assert';
import {
  MITRE_TACTICS,
  CORE_TECHNIQUES,
  generateMitreCoverageMatrix,
  generateMitreMarkdownReport,
  saveMitreReport
} from '../src/engine/mitre.js';

async function runTests() {
  console.log('🧪 Testing MITRE ATT&CK® Matrix & Coverage Gap Engine...');

  // Test 1: Tactics and Techniques catalog
  assert(Array.isArray(MITRE_TACTICS) && MITRE_TACTICS.length === 14, 'Must have 14 Enterprise Tactics');
  assert(Array.isArray(CORE_TECHNIQUES) && CORE_TECHNIQUES.length >= 10, 'Must have core techniques list');
  console.log('✔ Test 1 passed: MITRE Tactics and Core Techniques catalog validated.');

  // Test 2: Generate Coverage Matrix
  const matrixReport = generateMitreCoverageMatrix();
  assert(matrixReport.totalTechniques > 0);
  assert(typeof matrixReport.coveragePercent === 'number');
  assert(matrixReport.coveragePercent >= 0 && matrixReport.coveragePercent <= 100);
  assert(Array.isArray(matrixReport.matrix));
  assert(matrixReport.tacticBreakdown && typeof matrixReport.tacticBreakdown === 'object');
  console.log(`✔ Test 2 passed: generateMitreCoverageMatrix calculated ${matrixReport.coveragePercent}% coverage across ${matrixReport.totalTechniques} techniques.`);

  // Test 3: Generate Markdown Report
  const md = generateMitreMarkdownReport(matrixReport);
  assert(md.includes('# 🛡️ MITRE ATT&CK® Detection & Simulation Coverage Report'));
  assert(md.includes('| Tactic | Covered / Total | Coverage % |'));
  assert(md.includes('| Technique ID | Name | Tactic | Simulation Playbook | Active Sensors | Status |'));
  console.log('✔ Test 3 passed: generateMitreMarkdownReport generated GitHub Flavored Markdown report.');

  // Test 4: Save MITRE Report
  const saved = await saveMitreReport();
  assert(saved.reportId.startsWith('mitre-'));
  assert(saved.markdown.length > 0);
  assert(saved.matrix.totalTechniques > 0);
  console.log(`✔ Test 4 passed: saveMitreReport persisted and signed report ID: ${saved.reportId}.`);

  console.log('🎉 ALL 4 MITRE ATT&CK TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ MITRE Engine test failed:', err);
  process.exit(1);
});
