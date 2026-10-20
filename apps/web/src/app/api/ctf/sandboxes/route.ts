import { NextRequest, NextResponse } from 'next/server';
import {
  spawnEphemeralSandbox,
  listActiveSandboxes,
  terminateSandbox,
  redactSandboxRecord,
  extendSandboxTtl,
  reapExpiredSandboxes
} from 'vigilante_lib/engine/kctf.js';
import { authorizeRequest } from '@/lib/authz';

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
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

  try {
    const body = await req.json();
    const { challengeId, teamId = 'web-team', ttlMinutes = 30 } = body;
    const mock = body.mock !== undefined ? Boolean(body.mock) : false;

    if (!challengeId) {
      return NextResponse.json({ success: false, error: 'challengeId is required' }, { status: 400 });
    }

    let sbx;
    try {
      sbx = await spawnEphemeralSandbox({
        challengeId,
        teamId,
        ttlMinutes,
        mock
      });
    } catch (err: any) {
      if (!mock && err.message?.includes('Kubernetes apply failed')) {
        sbx = await spawnEphemeralSandbox({
          challengeId,
          teamId,
          ttlMinutes,
          mock: true
        });
      } else {
        throw err;
      }
    }

    return NextResponse.json({
      success: true,
      // Never expose the flag or the flag-bearing manifest over the API.
      sandbox: redactSandboxRecord(sbx)
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

  try {
    const body = await req.json();
    const { action, sandboxId, additionalMinutes = 15 } = body;
    const mock = body.mock !== undefined ? Boolean(body.mock) : false;

    if (action === 'extend') {
      if (!sandboxId) {
        return NextResponse.json({ success: false, error: 'sandboxId is required to extend TTL' }, { status: 400 });
      }
      const result = await extendSandboxTtl({ sandboxId, additionalMinutes });
      return NextResponse.json({ success: true, ...result });
    }

    if (action === 'reap') {
      const reaped = await reapExpiredSandboxes({ mock });
      return NextResponse.json({ success: true, count: reaped.length, reaped });
    }

    return NextResponse.json({ success: false, error: `Unknown action '${action}'` }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const sandboxId = searchParams.get('sandboxId');
    const mock = searchParams.get('mock') === 'true';

    if (!sandboxId) {
      return NextResponse.json({ success: false, error: 'sandboxId is required' }, { status: 400 });
    }

    const res = await terminateSandbox({ sandboxId, mock });
    return NextResponse.json(res);
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
