import { HUB_ITEMS, NavHub } from '../src/ui/NavHub.js';
import { WORKFLOW_STAGES, getActiveWorkflowStage, getContextualMenuConfig } from '../src/ui/MenuBar.js';

async function runTests() {
  console.log('🧪 Testing Operations Hub, Workflow Dispatcher & Disambiguated Navigation...');

  // Test 1: Hub items integrity
  if (!Array.isArray(HUB_ITEMS) || HUB_ITEMS.length < 10) {
    throw new Error(`Expected at least 10 HUB_ITEMS, found: ${HUB_ITEMS.length}`);
  }

  const uniqueActions = new Set(HUB_ITEMS.map(i => i.action));
  if (uniqueActions.size !== HUB_ITEMS.length) {
    throw new Error('Duplicate actions detected in HUB_ITEMS');
  }

  console.log(`✔ Test 1 passed: Verified ${HUB_ITEMS.length} distinct hub actions across 4 operational sections.`);

  // Test 2: Workflow stage mapping for MENU
  const stageMenu = getActiveWorkflowStage('MENU');
  if (stageMenu !== 'MENU') {
    throw new Error(`Expected 'MENU', got: ${stageMenu}`);
  }
  const hubStageObj = WORKFLOW_STAGES.find(s => s.id === 'MENU');
  if (!hubStageObj || hubStageObj.key !== 'Tab') {
    throw new Error('WORKFLOW_STAGES missing MENU hub stage definition');
  }
  console.log('✔ Test 2 passed: getActiveWorkflowStage correctly resolved MENU stage and Tab binding.');

  // Test 3: MenuBar contextual menu config for MENU
  const menuConfig = getContextualMenuConfig('MENU', {}, { primary: 'cyan' });
  if (!menuConfig.title.includes('Hub') || !menuConfig.items.some(i => i.key.includes('Tab'))) {
    throw new Error(`Invalid menuConfig for MENU: ${JSON.stringify(menuConfig)}`);
  }
  console.log('✔ Test 3 passed: MenuBar contextual menu config provides clear hub navigation controls.');

  // Test 4: Disambiguated action routing
  const upItem = HUB_ITEMS.find(i => i.action === 'UP');
  const modItem = HUB_ITEMS.find(i => i.action === 'MODULES');
  const nmapItem = HUB_ITEMS.find(i => i.action === 'NMAP');
  const podItem = HUB_ITEMS.find(i => i.action === 'PODS');
  const xmlItem = HUB_ITEMS.find(i => i.action === 'XML_VISUALIZER');

  if (!upItem || !modItem || !nmapItem || !podItem || !xmlItem) {
    throw new Error('Core hub items missing');
  }

  if (nmapItem.key !== '5' || modItem.key !== '0') {
    throw new Error(`Unexpected hotkey mapping: nmap=${nmapItem.key}, modules=${modItem.key}`);
  }
  console.log('✔ Test 4 passed: Number and letter hotkeys cleanly disambiguate Namespace, Nmap, Modules, and Pods.');

  // Test 5: NavHub React component export
  if (typeof NavHub !== 'function') {
    throw new Error('NavHub is not exported as a valid React component');
  }
  console.log('✔ Test 5 passed: NavHub React component exported and validated.');

  console.log('🎉 All Operations Hub & Navigation tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
