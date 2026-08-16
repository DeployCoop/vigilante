import { getActiveWorkflowStage, getContextualMenuConfig, WORKFLOW_STAGES } from '../src/ui/MenuBar.js';

async function runTests() {
  console.log('🧪 Testing Globally Context-Sensitive Menu & Workflow Engine...');

  // Test 1: Workflow Stages mapping
  if (WORKFLOW_STAGES.length !== 6) {
    throw new Error(`Expected 6 workflow stages, got: ${WORKFLOW_STAGES.length}`);
  }
  const stages = WORKFLOW_STAGES.map(s => s.id);
  const expectedStages = ['UP', 'MODULES', 'STATUS', 'PODS', 'NMAP', 'VISUALIZER'];
  for (const exp of expectedStages) {
    if (!stages.includes(exp)) throw new Error(`Missing workflow stage: ${exp}`);
  }
  console.log('✔ Test 1 passed: WORKFLOW_STAGES defined canonical progression (UP -> MODULES -> STATUS -> PODS -> NMAP -> VISUALIZER).');

  // Test 2: getActiveWorkflowStage mapping
  if (getActiveWorkflowStage('RUNNING') !== 'UP') throw new Error('Expected RUNNING -> UP');
  if (getActiveWorkflowStage('MODULES') !== 'MODULES') throw new Error('Expected MODULES -> MODULES');
  if (getActiveWorkflowStage('DASHBOARD') !== 'STATUS') throw new Error('Expected DASHBOARD -> STATUS');
  if (getActiveWorkflowStage('PODS') !== 'PODS') throw new Error('Expected PODS -> PODS');
  if (getActiveWorkflowStage('NMAP') !== 'NMAP') throw new Error('Expected NMAP -> NMAP');
  if (getActiveWorkflowStage('XML_VISUALIZER') !== 'VISUALIZER') throw new Error('Expected XML_VISUALIZER -> VISUALIZER');
  console.log('✔ Test 2 passed: getActiveWorkflowStage correctly resolved stages.');

  // Test 3: XML_VISUALIZER Contextual Action Keys
  const visualizerConfig = getContextualMenuConfig('XML_VISUALIZER', { selectedHost: { ip: '10.0.1.5' } });
  const vizKeys = visualizerConfig.items.map(i => i.key);
  if (!vizKeys.includes('p')) throw new Error('Expected [p] in XML_VISUALIZER menu');
  if (!vizKeys.includes('b')) throw new Error('Expected [b] in XML_VISUALIZER menu');
  if (!vizKeys.includes('m')) throw new Error('Expected [m] in XML_VISUALIZER menu');
  if (!vizKeys.includes('h')) throw new Error('Expected [h] in XML_VISUALIZER menu');
  if (!vizKeys.includes('d')) throw new Error('Expected [d] in XML_VISUALIZER menu');

  // Verify that in XML_VISUALIZER, 'p' is Ping and NOT Pods
  const pItem = visualizerConfig.items.find(i => i.key === 'p');
  if (!pItem.label.includes('Ping')) {
    throw new Error(`In visualizer, expected [p] to be Ping, got: ${pItem.label}`);
  }
  // Verify that in XML_VISUALIZER, 'b' is Bench and NOT Back
  const bItem = visualizerConfig.items.find(i => i.key === 'b');
  if (!bItem.label.includes('Bench')) {
    throw new Error(`In visualizer, expected [b] to be Bench, got: ${bItem.label}`);
  }
  console.log('✔ Test 3 passed: XML_VISUALIZER contextual menu maps [p]=Ping, [b]=Bench, [m]=MTR, [h]=HTTP, [d]=DNS.');

  // Test 4: PODS Contextual Action Keys
  const podsConfig = getContextualMenuConfig('PODS', {});
  const podKeys = podsConfig.items.map(i => i.key);
  if (!podKeys.includes('d') || !podKeys.includes('l') || !podKeys.includes('s')) {
    throw new Error('Expected describe, logs, and shell in PODS menu');
  }
  if (!podsConfig.nextStepHint?.key.includes('n')) {
    throw new Error('Expected next step hint for PODS to be Nmap [n]');
  }
  console.log('✔ Test 4 passed: PODS contextual menu maps [d]=Describe, [l]=Logs, [s]=Shell with next step [n] Nmap.');

  // Test 5: NMAP Contextual Action Keys
  const nmapConfig = getContextualMenuConfig('NMAP', {});
  const nmapKeys = nmapConfig.items.map(i => i.key);
  if (!nmapKeys.includes('n') || !nmapKeys.includes('i') || !nmapKeys.includes('t') || !nmapKeys.includes('p') || !nmapKeys.includes('x')) {
    throw new Error('Expected n, i, t, p, x in NMAP menu');
  }
  if (!nmapConfig.nextStepHint?.key.includes('x')) {
    throw new Error('Expected next step hint for NMAP to be XML Visualizer [x]');
  }
  console.log('✔ Test 5 passed: NMAP contextual menu maps scan controls with next step [x] XML Visualizer.');

  // Test 6: DASHBOARD Contextual Action Keys
  const dashConfig = getContextualMenuConfig('DASHBOARD', {});
  if (!dashConfig.nextStepHint?.key.includes('p')) {
    throw new Error('Expected next step hint for DASHBOARD to be Live Pods [p]');
  }
  console.log('✔ Test 6 passed: DASHBOARD contextual menu guides user to [p] Live Pods.');

  // Test 7: MODULES Contextual Action Keys
  const modConfig = getContextualMenuConfig('MODULES', {});
  if (!modConfig.nextStepHint?.key.includes('u')) {
    throw new Error('Expected next step hint for MODULES to be Deploy [u]');
  }
  console.log('✔ Test 7 passed: MODULES contextual menu guides user to [u] Deploy.');

  console.log('🎉 All Context-Sensitive Menu & Workflow Engine tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
