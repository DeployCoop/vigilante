import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  checkNmapInstalled,
  getNmapsDir,
  runNmapScan,
  listSavedNmapScans,
  readSavedScan,
  deleteSavedScan,
  calculateSubnetCidr,
  detectNetworkSubnets,
  SCAN_PROFILES
} from '../src/engine/nmap.js';
import { ensureVigilanteConfig } from '../src/engine/config.js';

async function runTests() {
  console.log('🧪 Testing Data Collection & Nmap Reconnaissance Engine...');

  const tempXdg = path.join(os.tmpdir(), `vigilante-nmap-test-${Math.random().toString(36).slice(2, 8)}`);
  process.env.XDG_CONFIG_HOME = tempXdg;

  try {
    await ensureVigilanteConfig();

    // Test 1: Nmap binary check
    const check = await checkNmapInstalled();
    if (!check.installed) {
      console.warn('⚠️ Nmap binary not found on test system, skipping live execution test.');
    } else {
      console.log(`✔ Test 1 passed: Nmap binary detected (version: ${check.version}).`);
    }

    // Test 2: Storage path verification
    const nmapsDir = getNmapsDir();
    if (!nmapsDir.endsWith(path.join('vigilante', 'nmaps'))) {
      throw new Error(`Invalid nmaps dir path: ${nmapsDir}`);
    }
    console.log(`✔ Test 2 passed: Nmaps storage directory resolved: ${nmapsDir}`);

    // Test 3: Scan profile definitions
    if (SCAN_PROFILES.length < 6) {
      throw new Error('Expected at least 6 predefined scan profiles including CIDR sweeps');
    }
    console.log(`✔ Test 3 passed: Verified ${SCAN_PROFILES.length} scan profiles (sweep, net-quick, net-service, quick, service, vuln, full, custom).`);

    // Test 4: Subnet CIDR calculation and network detection
    const calcCidr = calculateSubnetCidr('10.46.48.72', '255.255.255.0');
    if (calcCidr !== '10.46.48.0/24') {
      throw new Error(`Expected 10.46.48.0/24, got: ${calcCidr}`);
    }
    const subnets = detectNetworkSubnets();
    if (subnets.length < 3) {
      throw new Error('Expected network subnets to include local interfaces and cluster defaults');
    }
    console.log(`✔ Test 4 passed: calculateSubnetCidr and detectNetworkSubnets found ${subnets.length} CIDR ranges.`);

    // Test 5: Live scan execution against 127.0.0.1
    if (check.installed) {
      const logs = [];
      const scanResult = await runNmapScan({
        target: '127.0.0.1',
        profile: 'quick',
        onLog: (msg) => logs.push(msg)
      });

      if (!scanResult.nmapFilePath || !scanResult.xmlFilePath) {
        throw new Error('Expected nmap and xml output file paths');
      }

      const nmapExists = await fs.access(scanResult.nmapFilePath).then(() => true).catch(() => false);
      const xmlExists = await fs.access(scanResult.xmlFilePath).then(() => true).catch(() => false);

      if (!nmapExists || !xmlExists) {
        throw new Error('Scan result files were not created in $XDG_CONFIG_HOME/vigilante/nmaps/');
      }
      console.log(`✔ Test 5 passed: Executed Nmap scan and saved outputs to ${path.basename(scanResult.nmapFilePath)}`);

      // Test 6: CIDR Network Sweep scan execution (127.0.0.0/30)
      const cidrLogs = [];
      const cidrScan = await runNmapScan({
        target: '127.0.0.0/30',
        profile: 'sweep',
        onLog: (msg) => cidrLogs.push(msg)
      });

      if (!cidrScan.parsed || !cidrScan.parsed.isCidr) {
        throw new Error('Expected CIDR network scan to be parsed with isCidr: true');
      }
      if (cidrScan.parsed.discoveredHosts.length === 0) {
        throw new Error('Expected discovered hosts in 127.0.0.0/30 network sweep');
      }
      console.log(`✔ Test 6 passed: CIDR Network sweep on 127.0.0.0/30 discovered ${cidrScan.parsed.discoveredHosts.length} live hosts.`);

      // Test 7: listSavedNmapScans metadata parsing
      const savedScans = await listSavedNmapScans();
      if (savedScans.length !== 2) {
        throw new Error(`Expected 2 saved scans, found: ${savedScans.length}`);
      }
      const cidrItem = savedScans.find(s => s.isCidr);
      if (!cidrItem || !cidrItem.target || !cidrItem.summary) {
        throw new Error('Saved CIDR scan missing parsed metadata fields');
      }
      console.log(`✔ Test 7 passed: listSavedNmapScans discovered CIDR network map for '${cidrItem.target}' (${cidrItem.summary}).`);

      // Test 8: readSavedScan and deleteSavedScan
      const content = await readSavedScan(cidrItem.filePath);
      if (!content.includes('Nmap scan report') && !content.includes('Starting Nmap')) {
        throw new Error('Nmap report file content missing standard header');
      }

      for (const s of savedScans) {
        await deleteSavedScan(s.filePath);
      }
      const remainingScans = await listSavedNmapScans();
      if (remainingScans.length !== 0) {
        throw new Error('Expected 0 scans after deletion');
      }
      console.log('✔ Test 8 passed: readSavedScan and deleteSavedScan operated cleanly.');
    }

    console.log('🎉 All Data Collection & Nmap tests passed successfully!');
  } finally {
    try {
      await fs.rm(tempXdg, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  }
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
