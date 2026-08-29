import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';
import { saveEvidenceFile } from '../src/engine/evidence.js';

async function runTests() {
  console.log('🧪 Testing Vigilante Model Context Protocol (MCP) Server for LLMs...');

  const server = createVigilanteMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: 'vigilante-test-client', version: '0.1.0' },
    { capabilities: {} }
  );

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  // Test 1: List Resources
  const resourcesRes = await client.listResources();
  const resources = resourcesRes.resources || [];
  if (resources.length < 9) {
    throw new Error(`Expected at least 9 resources, got: ${resources.length}`);
  }
  const resourceUris = resources.map(r => r.uri);
  const expectedUris = [
    'vigilante://hosts',
    'vigilante://topology',
    'vigilante://evidence',
    'vigilante://pods',
    'vigilante://clusters',
    'vigilante://modules',
    'vigilante://scans',
    'vigilante://config',
    'vigilante://threats'
  ];
  for (const exp of expectedUris) {
    if (!resourceUris.includes(exp)) {
      throw new Error(`Missing expected resource: ${exp}`);
    }
  }
  console.log(`✔ Test 1 passed: Discovered ${resources.length} MCP resources (hosts, topology, evidence, pods, clusters, modules, scans, config, threats).`);

  // Test 2: List Resource Templates
  const templatesRes = await client.listResourceTemplates();
  const templates = templatesRes.resourceTemplates || [];
  if (templates.length < 4) {
    throw new Error(`Expected at least 4 resource templates, got: ${templates.length}`);
  }
  console.log(`✔ Test 2 passed: Discovered ${templates.length} parameterized resource templates.`);

  // Test 3: Read Core Resources
  const configContent = await client.readResource({ uri: 'vigilante://config' });
  if (!configContent.contents?.[0]?.text) {
    throw new Error('Failed to read vigilante://config');
  }
  const parsedCfg = JSON.parse(configContent.contents[0].text);
  if (!parsedCfg.config) {
    throw new Error('Config resource missing config object');
  }

  const modulesContent = await client.readResource({ uri: 'vigilante://modules' });
  const parsedModules = JSON.parse(modulesContent.contents[0].text);
  if (!Array.isArray(parsedModules.modules) || parsedModules.modules.length === 0) {
    throw new Error('Modules resource missing module definitions');
  }
  console.log(`✔ Test 3 passed: Successfully read static resources (config & ${parsedModules.modules.length} modules).`);

  // Test 4: List Available Tools
  const toolsRes = await client.listTools();
  const tools = toolsRes.tools || [];
  if (tools.length < 14) {
    throw new Error(`Expected at least 14 MCP tools, got: ${tools.length}`);
  }
  const toolNames = tools.map(t => t.name);
  const expectedTools = [
    'list_hosts',
    'get_host_details',
    'query_topology',
    'list_evidence',
    'run_diagnostic',
    'run_triage_capture',
    'run_nmap_scan',
    'verify_evidence_signature',
    'get_pods',
    'get_pod_logs',
    'describe_pod',
    'get_cluster_status',
    'list_threat_playbooks',
    'run_threat_simulation'
  ];
  for (const exp of expectedTools) {
    if (!toolNames.includes(exp)) {
      throw new Error(`Missing expected tool: ${exp}`);
    }
  }
  console.log(`✔ Test 4 passed: Discovered ${tools.length} callable MCP tools for LLMs.`);

  // Test 5: Call Tool: list_hosts
  const listHostsRes = await client.callTool({
    name: 'list_hosts',
    arguments: { state: 'all' }
  });
  const parsedHosts = JSON.parse(listHostsRes.content[0].text);
  if (!Array.isArray(parsedHosts.hosts)) {
    throw new Error('list_hosts did not return an array of hosts');
  }
  console.log(`✔ Test 5 passed: list_hosts tool executed successfully (${parsedHosts.total} hosts found).`);

  // Test 6: Call Tool: query_topology
  const topRes = await client.callTool({
    name: 'query_topology',
    arguments: {}
  });
  const parsedTop = JSON.parse(topRes.content[0].text);
  if (typeof parsedTop.networksCount !== 'number') {
    throw new Error('query_topology did not return network count');
  }
  console.log(`✔ Test 6 passed: query_topology tool executed successfully (${parsedTop.networksCount} networks).`);

  // Test 7: Call Tool: list_evidence & save dummy artifact
  await saveEvidenceFile('10.0.1.0/24', '10.0.1.5', 'mcp_test_evidence.txt', 'MCP evidence dump test content');
  const evidenceRes = await client.callTool({
    name: 'list_evidence',
    arguments: { network: '10.0.1.0_24' }
  });
  const parsedEv = JSON.parse(evidenceRes.content[0].text);
  if (!Array.isArray(parsedEv.networks)) {
    throw new Error('list_evidence did not return networks array');
  }
  console.log('✔ Test 7 passed: list_evidence tool discovered evidence vault hierarchy.');

  // Test 8: Call Tool: run_diagnostic (ping)
  const pingRes = await client.callTool({
    name: 'run_diagnostic',
    arguments: { tool: 'ping', host: '127.0.0.1', count: 1 }
  });
  const parsedPing = JSON.parse(pingRes.content[0].text);
  if (parsedPing.diagnostic !== 'ping' || !parsedPing.result) {
    throw new Error('run_diagnostic (ping) failed to return result');
  }
  console.log(`✔ Test 8 passed: run_diagnostic executed live ping probe (${parsedPing.result.alive ? 'Host Alive' : 'Unreachable'}).`);

  // Test 9: Call Tool: get_cluster_status
  const clusterRes = await client.callTool({
    name: 'get_cluster_status',
    arguments: { clusterName: 'vigilante-dev', domain: 'vigilante.local' }
  });
  const parsedCluster = JSON.parse(clusterRes.content[0].text);
  if (!parsedCluster.domain || !Array.isArray(parsedCluster.modules)) {
    throw new Error('get_cluster_status did not return domain/modules');
  }
  console.log(`✔ Test 9 passed: get_cluster_status returned cluster metadata and ${parsedCluster.modules.length} module states.`);

  // Test 10: Call Tool: list_threat_playbooks
  const playbooksRes = await client.callTool({
    name: 'list_threat_playbooks',
    arguments: {}
  });
  const parsedPlaybooks = JSON.parse(playbooksRes.content[0].text);
  if (!Array.isArray(parsedPlaybooks.playbooks) || parsedPlaybooks.playbooks.length < 7) {
    throw new Error('list_threat_playbooks did not return expected scenarios');
  }
  console.log(`✔ Test 10 passed: list_threat_playbooks returned ${parsedPlaybooks.playbooks.length} modular attack scenarios.`);

  await client.close();
  console.log('🎉 All Model Context Protocol (MCP) Server tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
