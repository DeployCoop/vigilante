import { NextResponse } from 'next/server';
import { authorizeRequest } from '@/lib/authz';
import { getTournamentEngine } from '@/lib/ctf-tournament-server';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const engine = await getTournamentEngine();
    const leaderboard = engine.getLeaderboard();
    const solveMatrix = engine.getSolveMatrix();
    const recentSolves = engine.solves.slice(-25).reverse();
    const svgChart = engine.renderScoreCurvesSvg({ width: 720, height: 260 });

    return NextResponse.json({
      success: true,
      tournament: {
        id: engine.id,
        title: engine.title,
        state: engine.state,
        activeMode: engine.activeMode,
        startTime: engine.startTime,
        totalTeams: engine.teams.size,
        totalSolves: engine.solves.length
      },
      leaderboard,
      recentSolves,
      solveMatrix,
      announcements: engine.announcements.slice(0, 5),
      svgChart
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
