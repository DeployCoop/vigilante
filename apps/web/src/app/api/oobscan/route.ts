import { NextResponse } from 'next/server';
import {
  listSavedOobScans,
  runOobScan,
  deleteSavedOobScan,
  checkOobscanInstalled,
  detectOobTargets,
  OOB_SCAN_PROFILES
} from 'vigilante_lib/engine/oobscan.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const denied = await authorizeRequest(request, 'scans:read');
  if (denied) return denied;

  try {
    const config = loadConfig();
    const domain = config.defaults?.domain || 'vigilante.local';
    const ip = config.defaults?.ip || '127.0.0.1';

    const oobscanInfo = await checkOobscanInstalled();
    const targets = detectOobTargets({ ip, domain });
    const scans = await listSavedOobScans().catch(() => []);

    return NextResponse.json({
      success: true,
      oobscanInfo,
      targets,
      profiles: OOB_SCAN_PROFILES.map((p) => ({
        id: p.id,
        name: p.name,
        description: p.description
      })),
      scans
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        profiles: [],
        scans: []
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
    const { target = '127.0.0.1', profile = 'standard' } = body;

    const res = await runOobScan({
      target,
      profile
    });

    return NextResponse.json({
      success: true,
      result: res
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

export async function DELETE(request: Request) {
  const denied = await authorizeRequest(request, 'scans:run');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(request.url);

    const scanId = searchParams.get('scanId');

    if (!scanId) {
      return NextResponse.json({ success: false, error: 'scanId is required' }, { status: 400 });
    }

    await deleteSavedOobScan(scanId);
    return NextResponse.json({ success: true, deleted: scanId });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
