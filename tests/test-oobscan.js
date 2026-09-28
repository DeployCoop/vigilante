import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  checkOobscanInstalled,
  detectOobTargets,
  OOB_SCAN_PROFILES,
  parseOobReportContent,
  exportRakpHashes,
  listSavedOobScans,
  readSavedOobScan,
  deleteSavedOobScan
} from '../src/engine/oobscan.js';
import { getVigilanteOobscansDir, ensureVigilanteConfig } from '../src/engine/config.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runTests() {
  console.log('🧪 Testing Out-of-Band Management Scanner (oobscan) Engine & MCP...');

  // Test 1: Binary Installation Detection
  const installStatus = await checkOobscanInstalled();
  assert(typeof installStatus === 'object', 'installStatus must be an object');
  assert('installed' in installStatus, 'installStatus must have installed boolean');
  assert('path' in installStatus, 'installStatus must have path');
  assert('version' in installStatus, 'installStatus must have version');
  console.log(`✔ Test 1 passed: checkOobscanInstalled returned status (installed: ${installStatus.installed}).`);

  // Test 2: Scan Profiles & Profiles Definition
  assert(OOB_SCAN_PROFILES.quick, 'quick profile should exist');
  assert(OOB_SCAN_PROFILES.standard, 'standard profile should exist');
  assert(OOB_SCAN_PROFILES.ipmi, 'ipmi profile should exist');
  assert(OOB_SCAN_PROFILES.ipv6, 'ipv6 profile should exist');
  assert(OOB_SCAN_PROFILES.passive, 'passive profile should exist');

  const standardArgs = OOB_SCAN_PROFILES.standard.buildArgs('192.168.1.0/24', { disableLogins: true, ipmiFull: true });
  assert(standardArgs.includes('-targets'), 'Profile args must include -targets');
  assert(standardArgs.includes('192.168.1.0/24'), 'Profile args must include target');
  assert(standardArgs.includes('-no-logins'), 'disableLogins must add -no-logins');
  assert(standardArgs.includes('-ipmi-full'), 'ipmiFull must add -ipmi-full');
  console.log('✔ Test 2 passed: Scan profiles defined with proper argument builders.');

  // Test 3: Target Detection
  const targets = await detectOobTargets({ ip: '10.0.0.15', domain: 'vigilante.local' });
  assert(Array.isArray(targets), 'detectOobTargets must return array');
  assert(targets.length > 0, 'Should detect at least 1 target');
  const hasSubnetOrIpv6 = targets.some(t => t.type === 'subnet' || t.type === 'ipv6-multicast' || t.type === 'domain');
  assert(hasSubnetOrIpv6, 'Targets should include detected subnets or IPv6 multicast');
  console.log(`✔ Test 3 passed: detectOobTargets discovered ${targets.length} potential targets.`);

  // Test 4: NDJSON Report Parsing with IPMI, RAKP-2 Hashes, and Findings
  const sampleNdjson = [
    JSON.stringify({
      type: 'host',
      ip: '192.168.1.100',
      hostname: 'idrac-prod-node01.local',
      mac: '00:14:22:01:23:45',
      vendor: 'Dell Inc.',
      os: 'Dell Integrated Dell Remote Access Controller (iDRAC8)',
      device_type: 'BMC / Server Management',
      ports: [
        { port: 623, proto: 'udp', service: 'ipmi', banner: 'IPMI-2.0 RMCP+' },
        { port: 443, proto: 'tcp', service: 'https', banner: 'Dell iDRAC Web Administration' }
      ]
    }),
    JSON.stringify({
      type: 'service',
      ip: '192.168.1.100',
      port: 623,
      proto: 'udp',
      service: 'ipmi',
      cipher_suites: [0, 1, 2, 3],
      rakp_hash: '$rakp2$0$44656c6c$414243444546$4748494a4b4c$11223344556677889900aabbccddeeff00112233',
      rakp_username: 'root'
    }),
    JSON.stringify({
      type: 'finding',
      ip: '192.168.1.100',
      title: 'IPMI 2.0 RAKP Password Hash Disclosure (CVE-2013-4786)',
      severity: 'CRITICAL',
      cve: 'CVE-2013-4786',
      description: 'The remote IPMI 2.0 service allows remote attackers to obtain password hashes via RAKP Message 2.'
    }),
    JSON.stringify({
      type: 'credential',
      ip: '192.168.1.100',
      port: 443,
      username: 'root',
      password: 'calvin',
      valid: true,
      service: 'iDRAC'
    }),
    JSON.stringify({
      type: 'host',
      ip: '192.168.1.101',
      hostname: 'ilo-supermicro-02.local',
      vendor: 'Supermicro',
      os: 'Supermicro IPMI BMC',
      device_type: 'BMC',
      ports: [
        { port: 623, proto: 'udp', service: 'ipmi' },
        { port: 80, proto: 'tcp', service: 'http' }
      ]
    })
  ].join('\n');

  const parsed = parseOobReportContent(sampleNdjson, 'test-scan.jsonl');
  assert.strictEqual(parsed.summary.totalLines, 5, 'Should parse 5 NDJSON lines');
  assert.strictEqual(parsed.summary.hostsCount, 2, 'Should identify 2 hosts');
  assert.strictEqual(parsed.summary.bmcsCount, 2, 'Both hosts are BMCs');
  assert.strictEqual(parsed.summary.rakpHashesCount, 1, 'Should extract 1 RAKP hash');
  assert.strictEqual(parsed.summary.findingsCount, 1, 'Should extract 1 finding');
  assert.strictEqual(parsed.summary.defaultCredentialsCount, 1, 'Should extract 1 default credential');

  // Verify RAKP hashcat line format
  const hashObj = parsed.rakpHashes[0];
  assert.strictEqual(hashObj.ip, '192.168.1.100');
  assert.strictEqual(hashObj.username, 'root');
  assert(hashObj.hashcatLine.includes('rakp2'), 'Hashcat line must be formatted for hashcat -m 7300');
  console.log('✔ Test 4 passed: parseOobReportContent parsed NDJSON report with BMCs, RAKP hashes, and findings.');

  // Test 5: Saved Scan Persistence & Hash Export
  await ensureVigilanteConfig();
  const oobDir = getVigilanteOobscansDir();
  const testScanFilename = `oob-test-${Date.now()}.jsonl`;
  const testScanPath = path.join(oobDir, testScanFilename);
  await fs.writeFile(testScanPath, sampleNdjson, 'utf8');

  try {
    const savedScans = await listSavedOobScans();
    assert(savedScans.some(s => s.filename === testScanFilename), 'Saved scan must appear in listSavedOobScans()');

    const scanDetails = await readSavedOobScan(testScanFilename);
    assert.strictEqual(scanDetails.filename, testScanFilename);
    assert.strictEqual(scanDetails.summary.hostsCount, 2);

    const testExportPath = path.join(oobDir, `test-hashes-${Date.now()}.txt`);
    const exportResult = await exportRakpHashes(testExportPath);
    assert(exportResult.count >= 1, 'Should export at least 1 hash');
    assert.strictEqual(exportResult.filePath, testExportPath);

    const fileContent = await fs.readFile(testExportPath, 'utf8');
    assert(fileContent.includes('$rakp2$'), 'Exported file must contain RAKP-2 hash');

    // Clean up exported hash file
    await fs.unlink(testExportPath).catch(() => {});
    console.log('✔ Test 5 passed: listSavedOobScans, readSavedOobScan, and exportRakpHashes work correctly.');
  } finally {
    await deleteSavedOobScan(testScanFilename);
    const postDelete = await listSavedOobScans();
    assert(!postDelete.some(s => s.filename === testScanFilename), 'Scan should be deleted');
    console.log('✔ Test 6 passed: deleteSavedOobScan removes scan file cleanly.');
  }

  // Test 7: MCP Server Resources & Tools
  const server = createVigilanteMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client(
    { name: 'oobscan-test-client', version: '0.1.0' },
    { capabilities: {} }
  );

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  // Test Resources List
  const resList = await client.listResources();
  const oobScansRes = resList.resources.find(r => r.uri === 'vigilante://oob/scans');
  const oobHashesRes = resList.resources.find(r => r.uri === 'vigilante://oob/hashes');
  assert(oobScansRes, 'Resource vigilante://oob/scans must be registered');
  assert(oobHashesRes, 'Resource vigilante://oob/hashes must be registered');

  // Test Resource Templates List
  const tmplList = await client.listResourceTemplates();
  const oobTmpl = tmplList.resourceTemplates.find(t => t.uriTemplate === 'vigilante://oob/scan/{filename}');
  assert(oobTmpl, 'Resource template vigilante://oob/scan/{filename} must be registered');

  // Test Tools List
  const toolList = await client.listTools();
  const expectedTools = ['check_oobscan', 'run_oob_scan', 'list_oob_scans', 'get_oob_scan_details', 'export_rakp_hashes'];
  for (const toolName of expectedTools) {
    const foundTool = toolList.tools.find(t => t.name === toolName);
    assert(foundTool, `Tool ${toolName} must be registered in MCP server`);
  }

  // Test Call Tool: check_oobscan
  const checkRes = await client.callTool({ name: 'check_oobscan', arguments: {} });
  assert(checkRes.content && checkRes.content.length > 0, 'check_oobscan should return content');
  const checkData = JSON.parse(checkRes.content[0].text);
  assert('installed' in checkData, 'check_oobscan output should contain installed boolean');

  // Test Call Tool: list_oob_scans
  const listRes = await client.callTool({ name: 'list_oob_scans', arguments: {} });
  const listData = JSON.parse(listRes.content[0].text);
  assert(Array.isArray(listData.scans), 'list_oob_scans should return scans array');

  // Test Read Resource: vigilante://oob/scans
  const oobScansRead = await client.readResource({ uri: 'vigilante://oob/scans' });
  assert(oobScansRead.contents?.[0]?.text, 'Should read vigilante://oob/scans content');
  const oobScansParsed = JSON.parse(oobScansRead.contents[0].text);
  assert(Array.isArray(oobScansParsed.scans), 'scans must be array');

  // Test 8: OOBScanView Component Export & Instantiation
  const { OOBScanView } = await import('../src/index.js');
  assert(OOBScanView, 'OOBScanView must be exported from index.js');
  const React = (await import('react')).default;
  const el = React.createElement(OOBScanView, { domain: 'vigilante.local', ip: '127.0.0.1' });
  assert(React.isValidElement(el), 'React element for OOBScanView must be valid');
  console.log('✔ Test 8 passed: OOBScanView React Ink component instantiated successfully.');

  console.log('\n🎉 ALL 8 OOBSCAN TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
