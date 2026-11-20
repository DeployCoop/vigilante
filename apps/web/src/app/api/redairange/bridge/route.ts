import { NextRequest, NextResponse } from 'next/server';
import {
  buildAiCtfChallengeCatalog,
  provisionAiCtfChallenge,
  listBridgedAiChallenges,
  teardownBridgedAiChallenge,
  redactAiCtfRecord
} from 'vigilante_lib/engine/redairange.js';
import { loadConfig, requireCtfFlagSecret } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';
import { getTournamentEngine, persistTournamentState } from '@/lib/ctf-tournament-server';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const teamId = searchParams.get('teamId') || null;
    const config = loadConfig();
    const domain = config.defaults?.domain || 'vigilante.local';

    const bridged = await listBridgedAiChallenges({ teamId });
    const catalog = buildAiCtfChallengeCatalog({ domain });

    return NextResponse.json({
      success: true,
      count: bridged.length,
      bridged,
      catalog
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

  try {
    const body = await req.json().catch(() => ({}));
    const {
      scenarioId,
      teamId = 'web-operative',
      namespace = 'redairange'
    } = body;
    const mock = body.mock !== undefined ? Boolean(body.mock) : false;

    if (!scenarioId) {
      return NextResponse.json({ success: false, error: 'scenarioId is required' }, { status: 400 });
    }

    let ctfSecret: string;
    try {
      ctfSecret = requireCtfFlagSecret();
    } catch (secretErr: unknown) {
      return NextResponse.json({ success: false, error: errorMessage(secretErr) }, { status: 503 });
    }

    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';
    const provider = config.defaults?.clusterProvider || null;

    let record;
    try {
      record = await provisionAiCtfChallenge({
        scenarioId,
        teamId,
        domain,
        namespace,
        clusterName,
        provider,
        secretKey: ctfSecret,
        mock
      });
    } catch (err: unknown) {
      const msg = errorMessage(err);
      if (!mock && msg.includes('provisioning failed')) {
        record = await provisionAiCtfChallenge({
          scenarioId,
          teamId,
          domain,
          namespace,
          clusterName,
          provider,
          secretKey: ctfSecret,
          mock: true
        });
      } else {
        throw err;
      }
    }

    // Ensure the bridged challenge is registered in the active CTF Tournament Engine
    const engine = await getTournamentEngine();
    engine.secretKey = ctfSecret;
    if (!engine.challenges.has(record.challengeId)) {
      engine.addChallenge({
        id: record.challengeId,
        name: `AI RedTeam: ${record.scenarioName}`,
        category: 'ai-redteam',
        difficulty: 'Medium',
        port: record.port,
        protocol: 'TCP',
        isDynamicFlag: true,
        description: `Bridged RedAiRange AI security scenario (${record.scenarioId})`
      });
      await persistTournamentState(engine);
    }

    return NextResponse.json({
      success: true,
      // Never expose the flag or flag-bearing compose YAML over the API
      bridge: redactAiCtfRecord(record)
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:manage');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const bridgeId = searchParams.get('bridgeId');
    const mock = searchParams.get('mock') === 'true';

    if (!bridgeId) {
      return NextResponse.json({ success: false, error: 'bridgeId is required' }, { status: 400 });
    }

    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const provider = config.defaults?.clusterProvider || null;

    const result = await teardownBridgedAiChallenge({
      bridgeId,
      clusterName,
      provider,
      mock
    });

    return NextResponse.json(result, { status: result.success ? 200 : 404 });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
