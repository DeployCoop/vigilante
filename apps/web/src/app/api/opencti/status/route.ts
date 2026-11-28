import { NextResponse } from 'next/server';
import { checkOpenCtiConnection, readOpenCtiIndicatorCache } from 'vigilante_lib/engine/opencti.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const connection = await checkOpenCtiConnection();
    const cache = readOpenCtiIndicatorCache();
    return NextResponse.json({
      success: true,
      connection,
      cache: cache
        ? { count: cache.count, syncedAt: cache.syncedAt, url: cache.url }
        : null
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
