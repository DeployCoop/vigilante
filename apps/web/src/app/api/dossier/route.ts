import { NextResponse } from 'next/server';
import {
  listHostDossiers,
  getHostDossier,
  buildHostDossier
} from 'vigilante_lib/engine/dossier.js';
import { listPcapRecordings, replayPcap } from 'vigilante_lib/engine/traffic.js';
import { listBloodhoundIngests } from 'vigilante_lib/engine/bloodhound.js';
import { generateMitreCoverageMatrix } from 'vigilante_lib/engine/mitre.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const denied = await authorizeRequest(request, 'scans:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(request.url);

    const target = searchParams.get('target');
    const config = loadConfig();
    const defaultIp = config.defaults?.ip || '127.0.0.1';

    if (target) {
      const dossier = await getHostDossier(target);
      return NextResponse.json({ success: true, dossier });
    }

    let hostList = await listHostDossiers().catch(() => []);
    if (hostList.length === 0) {
      // Build a starter dossier for local IP if empty
      const initial = await buildHostDossier(defaultIp).catch(() => null);
      if (initial) {
        hostList = [
          {
            target: defaultIp,
            riskScore: initial.riskScore || 25,
            riskTier: initial.riskTier || 'LOW',
            riskColor: initial.riskColor || 'cyan',
            openPortsCount: initial.network?.openPorts?.length || 3,
            cvesCount: initial.vulnerabilities?.cves?.length || 0,
            isBmc: Boolean(initial.outOfBand?.detected),
            updatedAt: initial.updatedAt || new Date().toISOString()
          }
        ];
      }
    }

    const trafficPcaps = await listPcapRecordings().catch(() => []);
    const bhIngests = await listBloodhoundIngests().catch(() => []);
    const mitreMatrix = generateMitreCoverageMatrix().catch(() => null);

    return NextResponse.json({
      success: true,
      dossiers: hostList,
      trafficPcaps,
      bhIngests,
      mitreMatrix
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        dossiers: []
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

    const { action = 'build', target = '127.0.0.1', pcapFile } = body;

    if (action === 'replay' && pcapFile) {
      const replayResult = await replayPcap(pcapFile);
      return NextResponse.json({ success: true, replayResult });
    }

    const dossier = await buildHostDossier(target);
    return NextResponse.json({
      success: true,
      dossier
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
