import assert from 'node:assert';
import { BattleStationView } from '../src/ui/BattleStationView.js';
import { CommandPalette, COMMAND_ITEMS } from '../src/ui/CommandPalette.js';
import { KspmView } from '../src/ui/KspmView.js';
import { AuditView } from '../src/ui/AuditView.js';

async function runTests() {
  console.log('🧪 Testing BattleStation & Command Palette TUI Components...');

  // Test 1: Validate BattleStationView Export
  assert(typeof BattleStationView === 'object' || typeof BattleStationView === 'function', 'BattleStationView must be exported');
  console.log('✔ Test 1 passed: BattleStationView component exported.');

  // Test 2: Validate CommandPalette Export & Catalog
  assert(typeof CommandPalette === 'object' || typeof CommandPalette === 'function', 'CommandPalette must be exported');
  assert(Array.isArray(COMMAND_ITEMS) && COMMAND_ITEMS.length >= 10, 'COMMAND_ITEMS catalog must be populated');

  const bsItem = COMMAND_ITEMS.find(i => i.action === 'BATTLESTATION');
  assert(bsItem, 'Must have BATTLESTATION launcher item in CommandPalette');

  const kspmItem = COMMAND_ITEMS.find(i => i.action === 'KSPM');
  assert(kspmItem, 'Must have KSPM launcher item in CommandPalette');

  const auditItem = COMMAND_ITEMS.find(i => i.action === 'AUDIT');
  assert(auditItem, 'Must have AUDIT launcher item in CommandPalette');
  console.log(`✔ Test 2 passed: CommandPalette catalog contains ${COMMAND_ITEMS.length} indexed commands & views.`);

  // Test 3: Validate KspmView & AuditView Exports
  assert(typeof KspmView === 'object' || typeof KspmView === 'function', 'KspmView must be exported');
  assert(typeof AuditView === 'object' || typeof AuditView === 'function', 'AuditView must be exported');
  console.log('✔ Test 3 passed: KspmView and AuditView components exported.');

  console.log('🎉 ALL 3 BATTLESTATION & UI TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ BattleStation test failed:', err);
  process.exit(1);
});
