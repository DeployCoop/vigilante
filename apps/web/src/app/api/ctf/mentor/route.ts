import { NextRequest, NextResponse } from 'next/server';
import { getSocraticHintTier, parseCrashContext } from 'vigilante_lib/engine/llm.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

  try {
    const body = await req.json();

    const { action, tier = 1, userQuery, crashLog, challengeId, provider } = body;

    if (action === 'crash') {
      if (!crashLog) {
        return NextResponse.json({ success: false, error: 'crashLog is required for crash analysis' }, { status: 400 });
      }
      const diagnosis = parseCrashContext({
        crashLog,
        challenge: challengeId ? { id: challengeId, name: challengeId } : null
      });
      return NextResponse.json({ success: true, diagnosis });
    }

    // Default: Socratic Hint Tier. The analyst page's provider select
    // used to be decorative — the request never carried it, so every
    // hint came from the engine default. Forward it when given (the
    // engine validates against SUPPORTED_PROVIDERS).
    const hint = await getSocraticHintTier({
      tier: Number(tier),
      userQuery: userQuery || 'How do I analyze this vulnerability?',
      provider
    });

    return NextResponse.json({
      success: true,
      hint
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
