import assert from 'node:assert';
import { runAgentSocInvestigation, generateSocInvestigatorReport } from '../src/engine/agent-soc.js';
import { listActiveContainments } from '../src/engine/soar.js';
import { listNistIncidents } from '../src/engine/nist.js';

async function runTests() {
  console.log('🧪 Testing Autonomous Agentic SOC Loop (ReAct Investigator)...');

  // Test 1: Run ReAct Investigation on suspicious workload
  const targetPod = 'auth-service-malicious-pod';
  const incidentId = `IR-TEST-${Date.now().toString(36).toUpperCase()}`;

  const result = await runAgentSocInvestigation({
    target: targetPod,
    incidentId,
    triggerAlert: {
      title: 'Privilege escalation setuid execution & outbound C2 beacon',
      source: 'Falco eBPF',
      details: 'Container spawned bash with root privileges; attempted outbound TLS connection to known C2 IP'
    },
    automatedContainment: true
  });

  assert(result.incidentId === incidentId, 'Incident ID must match');
  assert(result.target === targetPod, 'Target must match');
  assert(Array.isArray(result.reasoningTrace) && result.reasoningTrace.length >= 3, 'Reasoning trace must have multiple steps');
  assert(result.verdict && typeof result.verdict.threatLevel === 'string', 'Verdict must have threat level');
  assert(result.verdict.nistCategory.startsWith('CAT-'), 'Must assign NIST attack category');
  console.log(`✔ Test 1 passed: Autonomous ReAct investigation executed. Verdict: [${result.verdict.threatLevel}], Category: ${result.verdict.nistCategory}.`);

  // Test 2: Verify Automated SOAR Containment Triggered
  assert(result.containment && result.containment.containmentId, 'Automated containment must be executed');
  assert(result.containment.type === 'NETWORK_ISOLATION');
  const activeList = await listActiveContainments();
  const contained = activeList.find(c => c.containmentId === result.containment.containmentId);
  assert(contained && contained.active === true, 'Containment record must be active in vault');
  console.log(`✔ Test 2 passed: Automated SOAR containment confirmed active (${result.containment.containmentId}).`);

  // Test 3: Verify NIST Incident Record Created
  const incidents = await listNistIncidents();
  const foundInc = incidents.find(i => i.incidentId === incidentId);
  assert(foundInc, 'Incident record must be saved in evidence vault');
  assert(foundInc.target?.host === targetPod);
  console.log(`✔ Test 3 passed: NIST SP 800-61 Rev. 2 incident manifest verified in evidence vault.`);

  // Test 4: Generate Markdown Post-Mortem Report
  const md = generateSocInvestigatorReport(result);
  assert(md.includes('# 🤖 AUTONOMOUS AGENT SOC INVESTIGATION REPORT'));
  assert(md.includes('## 1. Executive Summary & Verdict'));
  assert(md.includes('## 2. ReAct Agent Reasoning & Investigative Trace'));
  assert(md.includes('## 3. MITRE ATT&CK® Techniques Identified'));
  assert(md.includes('## 4. Active Containment & SOAR Actions'));
  assert(md.includes('## 5. NIST SP 800-61 Post-Mortem & Eradication Guidance'));
  console.log('✔ Test 4 passed: Comprehensive NIST post-mortem Markdown report generated.');

  console.log('🎉 ALL 4 AUTONOMOUS AGENT SOC TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Agent SOC test failed:', err);
  process.exit(1);
});
