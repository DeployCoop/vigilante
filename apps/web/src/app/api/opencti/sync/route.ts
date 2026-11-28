import { NextRequest, NextResponse } from 'next/server';
import { syncOpenCtiIndicators } from 'vigilante_lib/engine/opencti.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'telemetry:write');
  if (denied) return denied;

  try {
    const body = await req.json().catch(() => ({}));
    const since = typeof body?.since === 'string' && body.since ? body.since : undefined;
    const result = await syncOpenCtiIndicators({ since });
    return NextResponse.json({ success: true, ...result });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
