import { NextResponse } from 'next/server';
import { generateKspmScorecard } from 'vigilante_lib/engine/kspm.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const scorecard = await generateKspmScorecard();
    return NextResponse.json({
      success: true,
      scorecard
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
