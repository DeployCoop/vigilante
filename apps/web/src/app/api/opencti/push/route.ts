import { NextRequest, NextResponse } from 'next/server';
import { pushStixBundleToOpenCti } from 'vigilante_lib/engine/opencti.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'telemetry:write');
  if (denied) return denied;

  try {
    const body = await req.json().catch(() => ({}));
    const bundle = body?.bundle ?? body;
    if (!bundle || typeof bundle !== 'object' || bundle.type !== 'bundle') {
      return NextResponse.json({ success: false, error: 'Body must be a STIX 2.1 bundle (or { bundle })' }, { status: 400 });
    }
    const result = await pushStixBundleToOpenCti(bundle);
    return NextResponse.json({ success: true, ...result });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
