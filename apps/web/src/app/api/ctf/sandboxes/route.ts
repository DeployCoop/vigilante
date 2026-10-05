import { NextRequest, NextResponse } from 'next/server';
import { spawnEphemeralSandbox, listActiveSandboxes, terminateSandbox } from 'vigilante_lib/engine/kctf.js';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const teamId = searchParams.get('teamId') || null;
    const sandboxes = await listActiveSandboxes({ teamId });
    return NextResponse.json({
      success: true,
      count: sandboxes.length,
      sandboxes
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { challengeId, teamId = 'web-team', ttlMinutes = 30 } = body;

    if (!challengeId) {
      return NextResponse.json({ success: false, error: 'challengeId is required' }, { status: 400 });
    }

    const sbx = await spawnEphemeralSandbox({
      challengeId,
      teamId,
      ttlMinutes,
      mock: true
    });

    return NextResponse.json({
      success: true,
      sandbox: sbx
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const sandboxId = searchParams.get('sandboxId');

    if (!sandboxId) {
      return NextResponse.json({ success: false, error: 'sandboxId is required' }, { status: 400 });
    }

    const res = await terminateSandbox({ sandboxId, mock: true });
    return NextResponse.json(res);
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
