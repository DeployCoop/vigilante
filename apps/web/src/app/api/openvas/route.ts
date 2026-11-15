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
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const denied = await authorizeRequest(request, 'scans:read');
  if (denied) return denied;

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
      const discoveredHosts: { ip: string }[] = [];
      try {
        const xmlScans = (await listSavedXmlScans()) as { hosts?: { ip: string }[] }[];
        xmlScans.forEach((s) => {
          (s.hosts || []).forEach((h) => {
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
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        profiles: SCAN_PROFILES
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, 'scans:run');
  if (denied) return denied;

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
      profile,
      namespace,
      clusterName
    });

    return NextResponse.json({
      success: true,
      report: result
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err)
      },
      { status: 500 }
    );
  }
}
