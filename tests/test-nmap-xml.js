import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { parseNmapXml, listSavedXmlScans, readXmlScan } from '../src/engine/nmap-xml.js';
import { ensureVigilanteConfig } from '../src/engine/config.js';

const SAMPLE_SINGLE_HOST_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -sV -p 80,443,631 127.0.0.1" start="1786888337" startstr="Sun Aug 16 08:52:17 2026" version="7.99" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="3" services="80,443,631"/>
<host starttime="1786888337" endtime="1786888343"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="VirtualBox"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
<hostname name="vigilante.local" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="nginx" version="1.24.0" method="probed" conf="10"><cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe></service><script id="http-title" output="Vigil SOC Landing"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="https" product="nginx" version="1.24.0" method="probed" conf="10"/><script id="ssl-cert" output="Subject: *.vigilante.local"/></port>
<port protocol="tcp" portid="631"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ipp" product="CUPS" version="2.4" method="probed" conf="10"/></port>
</ports>
<os>
<osmatch name="Linux 5.15 - 6.5" accuracy="98" line="1024"/>
</os>
<times srtt="25" rttvar="3755" to="100000"/>
</host>
<runstats><finished time="1786888343" timestr="Sun Aug 16 08:52:23 2026" summary="Nmap done at Sun Aug 16 08:52:23 2026; 1 IP address (1 host up) scanned in 6.26 seconds" elapsed="6.26" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>`;

const SAMPLE_CIDR_NETMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sn -T4 10.0.1.0/24" start="1786888000" startstr="Sun Aug 16 08:45:00 2026" version="7.99" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="0"/>
<host starttime="1786888000" endtime="1786888001"><status state="up" reason="arp-response"/>
<address addr="10.0.1.1" addrtype="ipv4"/>
<address addr="00:AA:BB:CC:DD:01" addrtype="mac" vendor="Cisco Systems"/>
<hostnames><hostname name="router.internal" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Embedded Web" version="1.0"/></port></ports>
</host>
<host starttime="1786888000" endtime="1786888001"><status state="up" reason="arp-response"/>
<address addr="10.0.1.5" addrtype="ipv4"/>
<address addr="00:AA:BB:CC:DD:05" addrtype="mac" vendor="Dell Inc"/>
<hostnames><hostname name="siem.vigilante.local" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="OpenSearch Dashboards" version="2.11"/></port>
<port protocol="tcp" portid="9200"><state state="open"/><service name="http" product="OpenSearch" version="2.11"/></port>
</ports>
</host>
<host starttime="1786888000" endtime="1786888001"><status state="down" reason="no-response"/>
<address addr="10.0.1.6" addrtype="ipv4"/>
</host>
<runstats><finished time="1786888002" timestr="Sun Aug 16 08:45:02 2026" summary="Nmap done at Sun Aug 16 08:45:02 2026; 256 IP addresses (2 hosts up) scanned in 2.10 seconds" elapsed="2.10" exit="success"/><hosts up="2" down="254" total="256"/>
</runstats>
</nmaprun>`;

async function runTests() {
  console.log('🧪 Testing Nmap XML Parser & Network Topology Backend...');

  const tempXdg = path.join(os.tmpdir(), `vigilante-xml-test-${Math.random().toString(36).slice(2, 8)}`);
  process.env.XDG_CONFIG_HOME = tempXdg;

  try {
    const configRes = await ensureVigilanteConfig();

    // Test 1: Single Host XML Parser
    const singleReport = parseNmapXml(SAMPLE_SINGLE_HOST_XML, 'nmap-127.0.0.1-test.xml');
    if (!singleReport.isValid) throw new Error(`Expected valid XML parse: ${singleReport.error}`);
    if (singleReport.hosts.length !== 1) throw new Error(`Expected 1 host, got: ${singleReport.hosts.length}`);
    const h1 = singleReport.hosts[0];
    if (h1.ip !== '127.0.0.1') throw new Error(`Expected 127.0.0.1, got: ${h1.ip}`);
    if (h1.mac !== '00:11:22:33:44:55' || h1.macVendor !== 'VirtualBox') throw new Error('MAC vendor parsing failed');
    if (h1.openPortsCount !== 3) throw new Error(`Expected 3 open ports, got: ${h1.openPortsCount}`);
    if (h1.bestOsMatch?.name !== 'Linux 5.15 - 6.5') throw new Error('OS matching failed');
    if (singleReport.totalScripts !== 2) throw new Error(`Expected 2 scripts, got: ${singleReport.totalScripts}`);
    console.log('✔ Test 1 passed: parseNmapXml extracted host addresses, MAC vendor, OS match, and NSE scripts.');

    // Test 2: Multi-Host CIDR Network Map XML Parser
    const cidrReport = parseNmapXml(SAMPLE_CIDR_NETMAP_XML, 'nmap-10.0.1.0_24-test.xml');
    if (!cidrReport.isValid) throw new Error(`Expected valid CIDR XML: ${cidrReport.error}`);
    if (!cidrReport.isCidr) throw new Error('Expected isCidr: true for CIDR network sweep');
    if (cidrReport.hosts.length !== 3) throw new Error(`Expected 3 host blocks, got: ${cidrReport.hosts.length}`);
    if (cidrReport.liveHosts.length !== 2) throw new Error(`Expected 2 live hosts, got: ${cidrReport.liveHosts.length}`);
    if (cidrReport.totalOpenPorts !== 3) throw new Error(`Expected 3 open ports across network, got: ${cidrReport.totalOpenPorts}`);
    console.log(`✔ Test 2 passed: parseNmapXml parsed CIDR network map (2 live hosts, 3 open ports across 10.0.1.0/24).`);

    // Test 3: XDG Storage and listSavedXmlScans
    const xmlDir = configRes.nmapsDir;
    const file1 = path.join(xmlDir, 'nmap-127.0.0.1-1786888337.xml');
    const file2 = path.join(xmlDir, 'nmap-10.0.1.0_24-1786888000.xml');

    await fs.writeFile(file1, SAMPLE_SINGLE_HOST_XML, 'utf8');
    await fs.writeFile(file2, SAMPLE_CIDR_NETMAP_XML, 'utf8');

    const savedXmls = await listSavedXmlScans();
    if (savedXmls.length !== 2) {
      throw new Error(`Expected 2 saved XML scans, found: ${savedXmls.length}`);
    }
    console.log(`✔ Test 3 passed: listSavedXmlScans discovered and parsed ${savedXmls.length} XML reports in XDG directory.`);

    // Test 4: readXmlScan
    const readReport = await readXmlScan(file2);
    if (!readReport.isValid || readReport.liveHosts.length !== 2) {
      throw new Error('readXmlScan failed to load XML file properly');
    }
    console.log('✔ Test 4 passed: readXmlScan parsed individual XML report file correctly.');

    console.log('🎉 All Nmap XML Parser & Backend tests passed successfully!');
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
