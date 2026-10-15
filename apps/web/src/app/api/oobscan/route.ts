import { NextResponse } from 'next/server';
import {
  listSavedOobScans,
  runOobScan,
  deleteSavedOobScan,
  exportRakpHashes,
  checkOobscanInstalled,
  detectOobTargets,
  OOB_SCAN_PROFILES
} from 'vigilante_lib/engine/oobscan.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action') || 'all';

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
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message,
        profiles: [],
        scans: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
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

export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const scanId = searchParams.get('scanId');

    if (!scanId) {
      return NextResponse.json({ success: false, error: 'scanId is required' }, { status: 400 });
    }

    await deleteSavedOobScan(scanId);
    return NextResponse.json({ success: true, deleted: scanId });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
