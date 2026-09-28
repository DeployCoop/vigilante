import {
  buildProcessLineageTree,
  detectAnomalousProcessLineage,
  renderAsciiProcessTree
} from '../src/engine/lineage.js';

async function runTests() {
  console.log('🧪 Testing Kernel-Native eBPF Lineage & Process Tree Engine...');

  const mockEvents = [
    { pid: 1, ppid: 0, comm: 'systemd', args: [] },
    { pid: 100, ppid: 1, comm: 'containerd', args: [] },
    { pid: 200, ppid: 100, comm: 'nginx', args: ['-g', 'daemon off;'], podName: 'ingress-nginx-4b7' },
    { pid: 250, ppid: 200, comm: '/bin/sh', args: ['-i'], podName: 'ingress-nginx-4b7' },
    { pid: 310, ppid: 250, comm: 'curl', args: ['-s', 'http://169.254.169.254/latest/meta-data/'], podName: 'ingress-nginx-4b7' },
    { pid: 400, ppid: 100, comm: 'kubelet', args: [] }
  ];

  // Test 1: Build Process Lineage Tree
  const tree = buildProcessLineageTree(mockEvents);
  if (tree.totalProcesses !== 6) throw new Error(`Expected 6 processes, got: ${tree.totalProcesses}`);
  if (tree.roots.length !== 1) throw new Error(`Expected 1 root process, got: ${tree.roots.length}`);
  console.log(`✔ Test 1 passed: Process lineage tree built with ${tree.totalProcesses} nodes.`);

  // Test 2: Detect Anomalous Process Lineage
  const anomalies = detectAnomalousProcessLineage(tree);
  if (anomalies.length !== 2) throw new Error(`Expected 2 anomalies, got: ${anomalies.length}`);
  const rce = anomalies.find(a => a.type === 'WEB_SERVER_SHELL_SPAWNED');
  const lolbin = anomalies.find(a => a.type === 'LOLBIN_NETWORK_FETCH');
  if (!rce || !lolbin) throw new Error('Missing expected anomaly types');
  if (rce.mitreTechnique !== 'T1059.004' || lolbin.mitreTechnique !== 'T1105') {
    throw new Error('Invalid MITRE ATT&CK technique mapping');
  }
  console.log(`✔ Test 2 passed: Flagged ${anomalies.length} anomalous process executions (RCE shell & LOLBin egress).`);

  // Test 3: Render ASCII Process Tree
  const ascii = renderAsciiProcessTree(tree.roots[0]);
  if (!ascii.includes('systemd') || !ascii.includes('nginx') || !ascii.includes('[ANOMALY]')) {
    throw new Error('Invalid ASCII tree output');
  }
  console.log('✔ Test 3 passed: Rendered interactive ASCII process tree with anomaly markers.');

  console.log('🎉 ALL 3 PROCESS LINEAGE TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Lineage test failure:', err);
  process.exit(1);
});
