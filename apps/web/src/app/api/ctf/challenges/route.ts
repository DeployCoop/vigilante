import { NextResponse } from 'next/server';
import { CHALLENGE_TEMPLATES, CHALLENGE_CATEGORIES } from 'vigilante_lib/engine/kctf.js';
import { authorizeRequest } from '@/lib/authz';

export const dynamic = 'force-dynamic';

export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  return NextResponse.json({

    success: true,
    categories: CHALLENGE_CATEGORIES,
    challengesCount: CHALLENGE_TEMPLATES.length,
    challenges: CHALLENGE_TEMPLATES.map(c => ({
      id: c.id,
      name: c.name,
      category: c.category,
      difficulty: c.difficulty,
      port: c.port,
      protocol: c.protocol,
      serviceType: c.serviceType,
      description: c.description,
      hintsCount: c.hints?.length || 0
    }))
  });
}
