import { NextRequest, NextResponse } from 'next/server';
import { listSavedXmlScans, readXmlScan, generateTopology, geocodeIp } from 'vigilante_lib/engine/nmap-xml.js';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const scanId = searchParams.get('scanId');
    const layout = (searchParams.get('layout') as 'force2d' | 'radial' | 'tree') || 'force2d';

    const scans = await listSavedXmlScans();
    let targetScan = null;

    if (scanId) {
      const match = scans.find(s => s.id === scanId || s.filename === scanId || s.filePath === scanId);
      if (match) {
        targetScan = await readXmlScan(match.filePath);
      }
    }

    if (!targetScan && scans.length > 0) {
      targetScan = await readXmlScan(scans[0].filePath);
    }

    if (!targetScan) {
      // Fallback synthetic scan if no XML scans are yet in vault
      targetScan = {
        target: '10.0.1.0/24',
        args: 'nmap -sV -sC -O -T4 10.0.1.0/24',
        startStr: new Date().toISOString(),
        totalOpenPorts: 6,
        hosts: [
          {
            ip: '10.0.1.1',
            primaryHostname: 'gateway.vigilante.local',
            isUp: true,
            status: 'up',
            osFamily: 'Linux',
            primaryOs: 'Linux 5.15 (Ubuntu/Debian)',
            openPortsCount: 2,
            vulnerabilitiesCount: 0,
            riskScore: 20,
            riskTier: 'LOW',
            openPorts: [
              { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '8.9p1' },
              { port: 53, protocol: 'udp', service: 'domain', product: 'dnsmasq', version: '2.86' }
            ],
            traceroute: [{ hop: 1, ip: '10.0.1.1', rtt: 1.2 }]
          },
          {
            ip: '10.0.1.5',
            primaryHostname: 'k8s-control-plane',
            isUp: true,
            status: 'up',
            osFamily: 'Linux',
            primaryOs: 'Alpine Linux 3.19',
            openPortsCount: 3,
            vulnerabilitiesCount: 1,
            riskScore: 65,
            riskTier: 'HIGH',
            openPorts: [
              { port: 6443, protocol: 'tcp', service: 'kubernetes-api', product: 'k3s', version: 'v1.28.2+k3s1' },
              { port: 80, protocol: 'tcp', service: 'http', product: 'nginx', version: '1.24.0' },
              { port: 443, protocol: 'tcp', service: 'https', product: 'Traefik', version: '2.10.4' }
            ],
            traceroute: [{ hop: 1, ip: '10.0.1.1', rtt: 1.2 }, { hop: 2, ip: '10.0.1.5', rtt: 2.4 }]
          },
          {
            ip: '10.0.1.12',
            primaryHostname: 'vault-db.internal',
            isUp: true,
            status: 'up',
            osFamily: 'Linux',
            primaryOs: 'Debian GNU/Linux 12',
            openPortsCount: 1,
            vulnerabilitiesCount: 2,
            riskScore: 85,
            riskTier: 'CRITICAL',
            openPorts: [
              { port: 5432, protocol: 'tcp', service: 'postgresql', product: 'PostgreSQL Database', version: '15.4' }
            ],
            traceroute: [{ hop: 1, ip: '10.0.1.1', rtt: 1.2 }, { hop: 2, ip: '10.0.1.12', rtt: 3.1 }]
          },
          {
            ip: '198.51.100.42',
            primaryHostname: 'c2-threat-relay.net',
            isUp: true,
            status: 'up',
            osFamily: 'FreeBSD',
            primaryOs: 'FreeBSD 13.2',
            openPortsCount: 2,
            vulnerabilitiesCount: 3,
            riskScore: 95,
            riskTier: 'CRITICAL',
            openPorts: [
              { port: 4444, protocol: 'tcp', service: 'metasploit', product: 'Reverse TCP Listener', version: '6.0' },
              { port: 8080, protocol: 'tcp', service: 'http-proxy', product: 'Go-C2-Beacon', version: '2.1' }
            ],
            traceroute: [{ hop: 1, ip: '10.0.1.1', rtt: 1.2 }, { hop: 2, ip: '198.51.100.42', rtt: 45.8 }]
          }
        ]
      };
    }

    const topology = generateTopology(targetScan, { layout });

    // Enrich hosts with GeoIP coordinates
    const geocodedHosts = (targetScan.hosts || []).map((h: any) => {
      const geo = geocodeIp(h.ip);
      return {
        ...h,
        geo
      };
    });

    return NextResponse.json({
      success: true,
      scanTarget: targetScan.target,
      scanArgs: targetScan.args,
      startStr: targetScan.startStr,
      layout,
      topology,
      geocodedHosts,
      totalHosts: targetScan.hosts?.length || 0,
      totalOpenPorts: targetScan.totalOpenPorts || 0
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
