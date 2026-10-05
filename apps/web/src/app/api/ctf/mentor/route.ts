import { NextRequest, NextResponse } from 'next/server';
import { getSocraticHintTier, parseCrashContext } from 'vigilante_lib/engine/llm.js';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { action, tier = 1, userQuery, crashLog, challengeId } = body;

    if (action === 'crash') {
      if (!crashLog) {
        return NextResponse.json({ success: false, error: 'crashLog is required for crash analysis' }, { status: 400 });
      }
      const diagnosis = (parseCrashContext as any)({
        crashLog,
        challenge: challengeId ? { id: challengeId, name: challengeId } : null
      });
      return NextResponse.json({ success: true, diagnosis });
    }

    // Default: Socratic Hint Tier
    const hint = await getSocraticHintTier({
      tier: Number(tier),
      userQuery: userQuery || 'How do I analyze this vulnerability?'
    });

    return NextResponse.json({
      success: true,
      hint
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
