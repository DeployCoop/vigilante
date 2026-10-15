import { NextResponse } from 'next/server';
import {
  SCAN_PROFILES,
  checkOpenVasStatus,
  getOpenVasCredentials,
  runHostVulnerabilityScan,
  listSavedOpenVasReports
} from 'vigilante_lib/engine/openvas.js';
import { listSavedXmlScans } from 'vigilante_lib/engine/nmap-xml.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action') || 'status';
    const host = searchParams.get('host') || '127.0.0.1';

    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';

    if (action === 'status') {
      const status = await checkOpenVasStatus({ clusterName });
      const credentials = await getOpenVasCredentials({ namespace: status.namespace, clusterName });
      
      // Also get discovered hosts from Nmap scans to populate target picker
      let discoveredHosts: any[] = [];
      try {
        const xmlScans = await listSavedXmlScans();
        xmlScans.forEach((s: any) => {
          (s.hosts || []).forEach((h: any) => {
            if (!discoveredHosts.some((existing) => existing.ip === h.ip)) {
              discoveredHosts.push(h);
            }
          });
        });
      } catch {}

      const reports = await listSavedOpenVasReports('local_network', host).catch(() => []);

      return NextResponse.json({
        success: true,
        clusterName,
        domain,
        status,
        credentials,
        profiles: SCAN_PROFILES,
        discoveredHosts,
        reports
      });
    }

    if (action === 'reports') {
      const reports = await listSavedOpenVasReports('local_network', host);
      return NextResponse.json({
        success: true,
        reports
      });
    }

    return NextResponse.json({ success: false, error: 'Unknown action' }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message,
        profiles: SCAN_PROFILES
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { host, profile = 'full-and-fast', namespace = null } = body;

    if (!host) {
      return NextResponse.json({ success: false, error: 'Target host is required' }, { status: 400 });
    }

    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';

    const hostObj = typeof host === 'string' ? { ip: host, ports: [] } : host;

    const result = await runHostVulnerabilityScan({
      host: hostObj,
      profileId: profile,
      namespace,
      clusterName
    });

    return NextResponse.json({
      success: true,
      report: result
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message
      },
      { status: 500 }
    );
  }
}
