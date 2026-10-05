import { NextRequest, NextResponse } from 'next/server';
import { simulateFalcoEvent, evaluateFalcoSoarAction } from 'vigilante_lib/engine/falco.js';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => ({}));
    const scenario = body.scenario || 'shell-spawn';
    const overrides = body.overrides || {};

    const event = simulateFalcoEvent(scenario, overrides);
    const soarAction = evaluateFalcoSoarAction(event);

    return NextResponse.json({
      success: true,
      event,
      soarAction
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
