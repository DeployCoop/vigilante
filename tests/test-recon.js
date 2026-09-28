import assert from 'node:assert';
import {
  RECON_PROFILES,
  checkReconToolsInstalled,
  parseNaabuOutput,
  parseHttpxOutput,
  probePortsNative,
  probeHttpNative,
  reconToTopology,
  runReconScan,
  listSavedReconScans
} from '../src/engine/recon.js';

async function runTests() {
  console.log('🧪 Testing Recon Engine (Naabu & Httpx)...');

  // Test 1: Profiles
  assert(Array.isArray(RECON_PROFILES) && RECON_PROFILES.length >= 3, 'Should have recon profiles');
  const fastProfile = RECON_PROFILES.find(p => p.id === 'fast-ports');
  assert(fastProfile, 'fast-ports profile must exist');
  const fastArgs = fastProfile.buildArgs('10.0.0.1', { topPorts: 50, rate: 500 });
  assert(fastArgs.includes('-host') && fastArgs.includes('10.0.0.1'), 'Naabu args should contain host');
  assert(fastArgs.includes('50'), 'Naabu args should contain top ports');
  console.log('✔ Test 1 passed: Recon profiles and argument builder validated.');

  // Test 2: Tool checks
  const toolStatus = await checkReconToolsInstalled();
  assert(toolStatus.naabu && toolStatus.httpx, 'checkReconToolsInstalled returns status for naabu & httpx');
  console.log(`✔ Test 2 passed: Recon tools status checked (Naabu runner: ${toolStatus.naabu.runner}, Httpx runner: ${toolStatus.httpx.runner}).`);

  // Test 3: Parse Naabu output
  const sampleNaabu = `
{"host":"192.168.1.10","ip":"192.168.1.10","port":22}
{"host":"192.168.1.10","ip":"192.168.1.10","port":80}
192.168.1.10:443
`;
  const parsedPorts = parseNaabuOutput(sampleNaabu);
  assert.strictEqual(parsedPorts.length, 3, 'Should parse 3 ports');
  assert.strictEqual(parsedPorts[0].port, 22);
  assert.strictEqual(parsedPorts[1].port, 80);
  assert.strictEqual(parsedPorts[2].port, 443);
  console.log('✔ Test 3 passed: parseNaabuOutput successfully parsed JSON and host:port lines.');

  // Test 4: Parse Httpx output
  const sampleHttpx = `
{"url":"https://example.com","input":"example.com","port":443,"title":"Example Domain","webserver":"ECS (dcb/7ea2)","status_code":200,"tech":["Cloudflare","HSTS"]}
`;
  const parsedWeb = parseHttpxOutput(sampleHttpx);
  assert.strictEqual(parsedWeb.length, 1);
  assert.strictEqual(parsedWeb[0].title, 'Example Domain');
  assert.strictEqual(parsedWeb[0].status_code, 200);
  assert.deepStrictEqual(parsedWeb[0].tech, ['Cloudflare', 'HSTS']);
  console.log('✔ Test 4 passed: parseHttpxOutput successfully parsed HTTP service details.');

  // Test 5: Topology conversion
  const topo = reconToTopology({
    target: '192.168.1.10',
    openPorts: parsedPorts,
    webServices: parsedWeb
  });
  assert(topo.nodes.length >= 2, 'Should create target and service nodes');
  assert(topo.links.length >= 1, 'Should create link from target to service');
  console.log('✔ Test 5 passed: reconToTopology generated valid graph nodes and links.');

  // Test 6: Run recon scan with native fallback
  const scan = await runReconScan('127.0.0.1', 'fast-ports', { topPorts: 5 });
  assert(scan.id && scan.filePath, 'runReconScan should return scan id and path');
  assert.strictEqual(scan.target, '127.0.0.1');

  const saved = await listSavedReconScans();
  assert(saved.length >= 1, 'Should find saved scan in directory');
  console.log('✔ Test 6 passed: runReconScan executed, signed evidence, and listed saved scans.');

  console.log('🎉 ALL 6 RECON TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ Recon test failed:', err);
  process.exit(1);
});
