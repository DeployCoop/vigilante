import assert from 'node:assert';
import { generateTopology, generateHeadlessSvg } from '../src/engine/nmap-xml.js';
import { buildHostDossier } from '../src/engine/dossier.js';

async function runTests() {
  console.log('🧪 Testing NastyMap 2.0 Cyber Attack Graph & Blast Radius Overlay...');

  // Pre-seed a host dossier so that topology can decorate it
  const sampleIp = '10.42.0.77';
  await buildHostDossier(sampleIp);

  // Mock Nmap XML Scan Data with our sample host and other nodes
  const mockScan = {
    id: 'test-scan-v2',
    target: '10.42.0.0/24',
    hosts: [
      {
        ip: sampleIp,
        hostname: 'compromised-workload.local',
        status: 'up',
        ports: [
          { port: 22, protocol: 'tcp', state: 'open', service: 'ssh' },
          { port: 80, protocol: 'tcp', state: 'open', service: 'http' },
          { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' }
        ]
      },
      {
        ip: '10.42.0.88',
        hostname: 'domain-controller.local',
        status: 'up',
        ports: [
          { port: 88, protocol: 'tcp', state: 'open', service: 'kerberos' },
          { port: 389, protocol: 'tcp', state: 'open', service: 'ldap' },
          { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' }
        ]
      }
    ]
  };

  // Test 1: Topology Generation with Dossier Ingestion
  const graph = generateTopology(mockScan);
  assert(graph && Array.isArray(graph.nodes) && Array.isArray(graph.links));
  assert(graph.nodes.length >= 2, 'Must have at least 2 nodes');

  const hostNode = graph.nodes.find(n => n.id === sampleIp || (n.label && n.label.includes(sampleIp)) || n.ip === sampleIp);
  assert(hostNode, 'Must find host node');
  assert(typeof hostNode.riskScore === 'number', 'Node must have riskScore injected');
  assert(typeof hostNode.riskTier === 'string', 'Node must have riskTier injected');
  assert(typeof hostNode.riskColor === 'string', 'Node must have riskColor injected');
  console.log(`✔ Test 1 passed: Host node decorated with Risk Score ${hostNode.riskScore} [${hostNode.riskTier}].`);

  // Test 2: Lateral Attack Path Edges
  // Both nodes have port 445 (SMB) open, so a lateral movement link should be inferred
  const lateralLink = graph.links.find(l => l.relationship === 'lateral-attack-path' || l.style === 'dashed');
  assert(lateralLink, 'Must identify lateral movement attack path between SMB endpoints');
  assert(lateralLink.technique === 'T1021.002' || lateralLink.relationship === 'lateral-attack-path');
  console.log(`✔ Test 2 passed: Lateral attack path link detected between ${lateralLink.source} and ${lateralLink.target}.`);

  // Test 3: Headless SVG Generation with Risk Badges
  const svg = generateHeadlessSvg(graph, { title: 'NastyMap 2.0 Test' });
  assert(svg.includes('<svg'), 'Must produce SVG xml');
  assert(svg.includes('RISK'), 'SVG must include risk badges');
  assert(svg.includes('lateral-attack-path') || svg.includes('stroke-dasharray'), 'SVG must render lateral movement dashed edges');
  console.log('✔ Test 3 passed: Headless SVG generated with risk badges and attack path styling.');

  console.log('🎉 ALL 3 NASTYMAP 2.0 TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ NastyMap 2.0 test failed:', err);
  process.exit(1);
});
