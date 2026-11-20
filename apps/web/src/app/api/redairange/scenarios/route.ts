import { NextRequest, NextResponse } from 'next/server';
import {
  listRedAiRangeScenarios,
  generateScenarioComposeYaml,
  validateStackComposeYaml,
  evaluateAiAttackTelemetry
} from 'vigilante_lib/engine/redairange.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const kind = searchParams.get('kind');
    const difficulty = searchParams.get('difficulty');
    const search = searchParams.get('search');

    const scenarios = listRedAiRangeScenarios({ kind, difficulty, search }).map((s) => ({
      ...s,
      telemetry: evaluateAiAttackTelemetry(s.id)
    }));

    return NextResponse.json({
      success: true,
      count: scenarios.length,
      scenarios
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
    const action = body.action || 'validate';

    if (action === 'generate') {
      if (!body.scenarioId) {
        return NextResponse.json({ success: false, error: 'scenarioId is required' }, { status: 400 });
      }
      const composeYaml = generateScenarioComposeYaml(body.scenarioId, {
        port: body.port || null
      });
      const validation = validateStackComposeYaml(composeYaml);
      return NextResponse.json({
        success: true,
        scenarioId: body.scenarioId,
        composeYaml,
        validation
      });
    }

    if (action === 'telemetry') {
      if (!body.scenarioId) {
        return NextResponse.json({ success: false, error: 'scenarioId is required' }, { status: 400 });
      }
      const telemetry = evaluateAiAttackTelemetry(body.scenarioId);
      return NextResponse.json({ success: true, telemetry });
    }

    const validation = validateStackComposeYaml(body.rawYaml || '');
    return NextResponse.json({
      success: true,
      ...validation
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 400 });
  }
}
