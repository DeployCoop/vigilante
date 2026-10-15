import { NextResponse } from 'next/server';
import {
  WARGAME_SCENARIOS,
  runPurpleTeamSimulation,
  calculatePurpleScorecard
} from 'vigilante_lib/engine/purpleteam.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const scenarios = Object.entries(WARGAME_SCENARIOS).map(([key, s]: [string, any]) => ({
      id: key,
      name: s.name,
      adversaryGroup: s.adversaryGroup,
      targetNamespace: s.targetNamespace,
      targetWorkload: s.targetWorkload,
      stepsCount: s.steps?.length || 0,
      steps: s.steps
    }));

    return NextResponse.json({
      success: true,
      scenarios
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        success: false,
        error: err.message,
        scenarios: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { scenarioKey = 'lateral-smb-exfil' } = body;

    const simulation = await runPurpleTeamSimulation(scenarioKey);
    const scorecard = calculatePurpleScorecard(simulation);

    return NextResponse.json({
      success: true,
      simulation,
      scorecard
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
