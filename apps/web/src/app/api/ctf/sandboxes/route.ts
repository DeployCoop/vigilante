import { NextRequest, NextResponse } from 'next/server';
import { spawnEphemeralSandbox, listActiveSandboxes, terminateSandbox, redactSandboxRecord } from 'vigilante_lib/engine/kctf.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const teamId = searchParams.get('teamId') || null;
    const sandboxes = await listActiveSandboxes({ teamId });
    return NextResponse.json({
      success: true,
      count: sandboxes.length,
      sandboxes
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

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
      // Never expose the flag or the flag-bearing manifest over the API.
      sandbox: redactSandboxRecord(sbx)
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);

    const sandboxId = searchParams.get('sandboxId');

    if (!sandboxId) {
      return NextResponse.json({ success: false, error: 'sandboxId is required' }, { status: 400 });
    }

    const res = await terminateSandbox({ sandboxId, mock: true });
    return NextResponse.json(res);
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
