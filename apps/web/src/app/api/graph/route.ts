import { NextRequest, NextResponse } from 'next/server';
import { buildCompositeAttackGraph, calculateBlastRadius, findShortestAttackPath } from 'vigilante_lib/engine/attackgraph.js';
import { authorizeRequest } from '@/lib/authz';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'telemetry:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);

    const targetNode = searchParams.get('target') || 'sa-cluster-admin';

    const graph = buildCompositeAttackGraph();
    const blast = calculateBlastRadius(targetNode, graph);
    const shortestPath = findShortestAttackPath('ext-attacker', 'sa-cluster-admin', graph);

    return NextResponse.json({
      success: true,
      graph,
      blast,
      shortestPath
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
