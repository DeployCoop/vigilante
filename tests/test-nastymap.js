import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import {
  parseNmapXml,
  generateTopology,
  compareNmapScans,
  generateHeadlessSvg,
  generateHtmlReport,
  geocodeIp,
  isPrivateIp
} from '../src/engine/nastymap/index.js';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';

console.log('🧪 Testing NastyMap Integration (Parser, Topology, Diff, Exporter, GeoIP & MCP)...');

// Sample XML for testing
const SAMPLE_XML_BASELINE = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -traceroute 10.0.1.0/24" start="1700000000" startstr="Mon Nov 15 10:00:00 2026" version="7.94">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <host starttime="1700000001" endtime="1700000010">
    <status state="up" reason="arp-response"/>
    <address addr="10.0.1.1" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Cisco Systems"/>
    <hostnames>
      <hostname name="gateway.vigilante.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.15" accuracy="98" line="1234"/>
      <osclass type="router" vendor="Linux" osfamily="Linux" accuracy="98"/>
    </os>
    <distance value="1"/>
    <trace port="80" proto="tcp">
      <hop ttl="1" ipaddr="10.0.1.1" rtt="0.45" host="gateway.vigilante.local"/>
    </trace>
    <times srtt="450" rttvar="100" to="100000"/>
  </host>
  <host starttime="1700000001" endtime="1700000010">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="web.vigilante.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache Tomcat" version="9.0.50"/>
        <script id="http-title" output="Vigilante SOC Dashboard"/>
      </port>
    </ports>
    <os>
      <osmatch name="Ubuntu Linux 22.04" accuracy="95"/>
    </os>
  </host>
  <runstats>
    <finished time="1700000010" timestr="Mon Nov 15 10:00:10 2026" elapsed="10.0" summary="Nmap done: 2 IP addresses (2 hosts up)" exit="success"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>`;

const SAMPLE_XML_CURRENT = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -O -traceroute 10.0.1.0/24" start="1700000500" startstr="Mon Nov 15 10:08:20 2026" version="7.94">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <host starttime="1700000501" endtime="1700000510">
    <status state="up" reason="arp-response"/>
    <address addr="10.0.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
  <host starttime="1700000501" endtime="1700000510">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache Tomcat" version="9.0.50"/>
      </port>
      <port protocol="tcp" portid="4444">
        <state state="open" reason="syn-ack"/>
        <service name="metasploit" product="Meterpreter Reverse Shell"/>
      </port>
    </ports>
  </host>
  <host starttime="1700000501" endtime="1700000510">
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.1.99" addrtype="ipv4"/>
    <hostnames>
      <hostname name="rogue-imposter.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft RDP"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1700000510" timestr="Mon Nov 15 10:08:30 2026" elapsed="10.0" summary="Nmap done: 3 IP addresses (3 hosts up)" exit="success"/>
    <hosts up="3" down="0" total="3"/>
  </runstats>
</nmaprun>`;

// Test 1: Parser
const parsed = parseNmapXml(SAMPLE_XML_BASELINE, 'baseline.xml');
assert.strictEqual(parsed.isValid, true);
assert.strictEqual(parsed.hosts.length, 2);
assert.strictEqual(parsed.hosts[0].ipv4, '10.0.1.1');
assert.strictEqual(parsed.hosts[0].primaryHostname, 'gateway.vigilante.local');
assert.strictEqual(parsed.hosts[0].ports.length, 2);
assert.strictEqual(parsed.hosts[0].ports[0].service.product, 'OpenSSH');
assert.strictEqual(parsed.hosts[0].ports[0].service.cpe[0], 'cpe:/a:openbsd:openssh:8.9p1');
assert.strictEqual(parsed.hosts[0].trace.hops.length, 1);
assert.strictEqual(parsed.hosts[0].osFamily, 'Linux');
console.log('✔ Test 1 passed: parseNmapXml parsed hosts, CPEs, OS matches, and traceroutes.');

// Test 2: GeoIP & Classification
assert.strictEqual(isPrivateIp('10.0.1.1'), true);
assert.strictEqual(isPrivateIp('192.168.1.50'), true);
assert.strictEqual(isPrivateIp('8.8.8.8'), false);

const geoLAN = geocodeIp('10.0.1.1');
assert.strictEqual(geoLAN.isPrivate, true);

const geoGoogle = geocodeIp('8.8.8.8');
assert.strictEqual(geoGoogle.isPrivate, false);
assert.strictEqual(geoGoogle.countryCode, 'USA');
console.log('✔ Test 2 passed: geocodeIp classified private LAN vs public WAN.');

// Test 3: Topology Layout Generator
const topoForce = generateTopology(parsed, { layout: 'force2d', width: 1000, height: 600 });
assert.ok(topoForce.nodes.length >= 3, 'Created scanner origin and host nodes');
assert.ok(topoForce.links.length >= 2, 'Created links between origin and hosts');
assert.strictEqual(topoForce.nodes[0].id, 'scanner-origin');

const topoRadial = generateTopology(parsed, { layout: 'radial' });
assert.strictEqual(topoRadial.nodes.length, topoForce.nodes.length);

const topoTree = generateTopology(parsed, { layout: 'tree' });
assert.strictEqual(topoTree.nodes.length, topoForce.nodes.length);
console.log('✔ Test 3 passed: generateTopology calculated force2d, radial, and tree layouts.');

// Test 4: Headless SVG & HTML Exporter
const svg = generateHeadlessSvg(topoForce, { title: 'Test Topology' });
assert.ok(svg.startsWith('<?xml'));
assert.ok(svg.includes('<svg'));
assert.ok(svg.includes('gateway.vigilante.local'));
assert.ok(svg.includes('10.0.1.1'));

const html = generateHtmlReport(parsed, topoForce);
assert.ok(html.includes('<!DOCTYPE html>'));
assert.ok(html.includes('NastyMap Security Topology Report'));
assert.ok(html.includes('10.0.1.1'));
assert.ok(html.includes('OpenSSH'));
console.log('✔ Test 4 passed: generateHeadlessSvg and generateHtmlReport generated standalone vector & HTML.');

// Test 5: Scan Diffing Engine
const parsedCurrent = parseNmapXml(SAMPLE_XML_CURRENT, 'current.xml');
const diff = compareNmapScans(parsed, parsedCurrent);

assert.strictEqual(diff.summary.hostsAdded, 1, '1 rogue host added (10.0.1.99)');
assert.strictEqual(diff.addedHosts[0].ip, '10.0.1.99');
assert.strictEqual(diff.summary.portsAdded, 2, '2 new ports opened (4444 on .10, 3389 on .99)');
assert.strictEqual(diff.modifiedHosts.length, 1, '1 host modified (.10 added port 4444)');
console.log('✔ Test 5 passed: compareNmapScans detected rogue host 10.0.1.99 and new port 4444.');

// Test 6: MCP Integration
const tmpDir = path.join(os.tmpdir(), `vigilante-test-nm-${Date.now().toString(36)}`);
process.env.XDG_CONFIG_HOME = tmpDir;
const nmapsDir = path.join(tmpDir, 'vigilante', 'nmaps');
await fs.mkdir(nmapsDir, { recursive: true });
await fs.writeFile(path.join(nmapsDir, 'baseline.xml'), SAMPLE_XML_BASELINE, 'utf8');
await fs.writeFile(path.join(nmapsDir, 'current.xml'), SAMPLE_XML_CURRENT, 'utf8');

const server = createVigilanteMcpServer();
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const client = new Client(
  { name: 'nastymap-test-client', version: '0.1.0' },
  { capabilities: {} }
);

await server.connect(serverTransport);
await client.connect(clientTransport);

try {
  const resList = await client.listResources();
  assert.ok(resList.resources.some(r => r.uri === 'vigilante://topology/svg'), 'vigilante://topology/svg exposed');
  assert.ok(resList.resources.some(r => r.uri === 'vigilante://topology/html'), 'vigilante://topology/html exposed');

  const toolsList = await client.listTools();
  assert.ok(toolsList.tools.some(t => t.name === 'diff_nmap_scans'), 'diff_nmap_scans tool registered');
  assert.ok(toolsList.tools.some(t => t.name === 'generate_topology_map'), 'generate_topology_map tool registered');

  const diffExec = await client.callTool({
    name: 'diff_nmap_scans',
    arguments: {
      baselineScan: 'baseline.xml',
      targetScan: 'current.xml'
    }
  });
  const parsedDiff = JSON.parse(diffExec.content[0].text);
  assert.strictEqual(parsedDiff.summary.hostsAdded, 1);
  assert.strictEqual(parsedDiff.addedHosts[0].ip, '10.0.1.99');

  const topoExec = await client.callTool({
    name: 'generate_topology_map',
    arguments: {
      scanFilename: 'baseline.xml',
      format: 'svg'
    }
  });
  assert.ok(topoExec.content[0].text.includes('<svg'));
  console.log('✔ Test 6 passed: MCP Tools diff_nmap_scans and generate_topology_map executed successfully.');
} finally {
  await client.close();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
}

console.log('\n🎉 All NastyMap Integration & Swapped Render tests passed successfully!\n');
