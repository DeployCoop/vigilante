import { NextRequest, NextResponse } from 'next/server';
import { CHALLENGE_TEMPLATES, CHALLENGE_CATEGORIES } from 'vigilante_lib/engine/kctf.js';
import { requireCtfFlagSecret } from 'vigilante_lib/engine/config.js';
import { authorizeRequest, resolveAuthzContext } from '@/lib/authz';
import { getTournamentEngine, persistTournamentState } from '@/lib/ctf-tournament-server';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const teamId = searchParams.get('teamId') || null;

    const engine = await getTournamentEngine();
    const team = teamId ? (engine.teams.get(teamId) || Array.from(engine.teams.values()).find(t => t.name.toLowerCase() === teamId.toLowerCase())) : null;

    const enrichedChallenges = CHALLENGE_TEMPLATES.map(c => {
      const chalState = engine.challenges.get(c.id);
      const solvesCount = chalState?.solvesCount || 0;
      const currentPoints = chalState?.currentPoints || 500;
      const firstBlood = chalState?.firstBlood || null;
      const isSolved = team ? team.solves.includes(c.id) : false;

      return {
        id: c.id,
        name: c.name,
        category: c.category,
        difficulty: c.difficulty,
        port: c.port,
        protocol: c.protocol,
        serviceType: c.serviceType,
        description: c.description,
        hintsCount: c.hints?.length || 0,
        currentPoints,
        solvesCount,
        firstBlood,
        solved: isSolved
      };
    });

    return NextResponse.json({
      success: true,
      categories: CHALLENGE_CATEGORIES,
      challengesCount: enrichedChallenges.length,
      challenges: enrichedChallenges,
      tournament: {
        id: engine.id,
        title: engine.title,
        state: engine.state,
        totalSolves: engine.solves.length,
        totalTeams: engine.teams.size
      }
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const authContext = await resolveAuthzContext(req);
    const body = await req.json().catch(() => ({}));
    const { challengeId, flag } = body;
    let { teamId, teamName } = body;

    if (!challengeId || !flag) {
      return NextResponse.json(
        { success: false, error: 'Both challengeId and flag are required' },
        { status: 400 }
      );
    }

    let ctfSecret: string;
    try {
      ctfSecret = requireCtfFlagSecret();
    } catch (secretErr: any) {
      return NextResponse.json(
        { success: false, error: secretErr.message },
        { status: 503 }
      );
    }

    // Default team identity to auth principal if available, or fallback
    if (!teamId && authContext.principal) {
      teamId = authContext.principal.id;
      teamName = teamName || authContext.principal.name;
    }
    if (!teamId) {
      teamId = 'web-operative';
      teamName = teamName || 'Web Operative';
    }

    const engine = await getTournamentEngine();
    engine.secretKey = ctfSecret;

    // Ensure team exists
    let team = engine.teams.get(teamId);
    if (!team) {
      for (const t of engine.teams.values()) {
        if (t.name.toLowerCase() === (teamName || teamId).toLowerCase()) {
          team = t;
          break;
        }
      }
    }

    if (!team) {
      const cleanName = (teamName || teamId).trim();
      team = {
        id: teamId,
        name: cleanName,
        email: null,
        members: [],
        token: 'tk_' + Math.random().toString(36).substring(2, 10),
        score: 0,
        jeopardyScore: 0,
        adAttackScore: 0,
        adDefenseScore: 0,
        adSlaScore: 0,
        kothScore: 0,
        lastSolveTimestamp: 0,
        solves: [],
        submissionsCount: 0,
        instanceCount: 0,
        registeredAt: new Date().toISOString()
      };
      engine.teams.set(team.id, team);
    }

    const result = engine.submitFlag({
      teamId: team.id,
      challengeId,
      flag
    });

    if (result.success) {
      await persistTournamentState(engine);
    }

    return NextResponse.json({
      ...result,
      teamId: team.id,
      teamName: team.name,
      challengeId
    }, { status: result.success ? 200 : 400 });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
