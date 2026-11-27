import { NextResponse } from 'next/server';
import { RedAiRangeModule } from 'vigilante_lib/modules/redairange/index.js';
import { listBridgedAiChallenges, REDAIRANGE_SCENARIOS } from 'vigilante_lib/engine/redairange.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'modules:read', { moduleId: 'redairange' });
  if (denied) return denied;

  try {
    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';
    const provider = config.defaults?.clusterProvider || null;

    const mod = new RedAiRangeModule();
    const status = await mod.status({ domain, clusterName, provider });
    const runtime = mod.getRuntimeInfo();
    const bridged = await listBridgedAiChallenges();

    return NextResponse.json({
      success: true,
      clusterName,
      domain,
      status,
      runtime,
      scenariosCount: REDAIRANGE_SCENARIOS.length,
      bridgedCount: bridged.length
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
