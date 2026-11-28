import { NextResponse } from 'next/server';
import { lookupOpenCtiObservable } from 'vigilante_lib/engine/opencti.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const value = (searchParams.get('value') || '').trim();
    if (!value) {
      return NextResponse.json({ success: false, error: 'Missing ?value= query parameter' }, { status: 400 });
    }
    const result = await lookupOpenCtiObservable(value);
    return NextResponse.json({ success: true, ...result });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
