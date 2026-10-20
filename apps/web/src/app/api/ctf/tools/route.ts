import { NextRequest, NextResponse } from 'next/server';
import {
  generateDeBruijnPattern,
  findDeBruijnOffset,
  autoIdentifyCipher,
  parseJwt,
  dragXorCrib,
  rsaWeakPrimes
} from 'vigilante_lib/engine/ctf-tools.js';
import { authorizeRequest } from '@/lib/authz';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const body = await req.json().catch(() => ({}));
    const tool = body.tool;

    if (tool === 'cyclic_generate') {
      const length = Math.min(Math.max(parseInt(body.length, 10) || 256, 16), 16384);
      const pattern = generateDeBruijnPattern(length);
      return NextResponse.json({ success: true, tool, length, pattern });
    }

    if (tool === 'cyclic_offset') {
      const { pattern, needle } = body;
      if (!needle) {
        return NextResponse.json(
          { success: false, error: 'needle (hex or ascii crash value) is required' },
          { status: 400 }
        );
      }
      const offset = findDeBruijnOffset(pattern, needle);
      return NextResponse.json({ success: true, tool, needle, offset });
    }

    if (tool === 'cipher_identify') {
      const { input } = body;
      if (!input || typeof input !== 'string') {
        return NextResponse.json(
          { success: false, error: 'input string is required for cipher analysis' },
          { status: 400 }
        );
      }
      const candidates = autoIdentifyCipher(input);
      return NextResponse.json({ success: true, tool, input, candidates });
    }

    if (tool === 'jwt_inspect') {
      const { token } = body;
      if (!token) {
        return NextResponse.json(
          { success: false, error: 'token string is required' },
          { status: 400 }
        );
      }
      const analysis = parseJwt(token);
      return NextResponse.json({ success: true, tool, ...analysis });
    }

    if (tool === 'xor_crib') {
      const { ct1, ct2, crib = 'VIGILANTE{' } = body;
      if (!ct1 || !ct2) {
        return NextResponse.json(
          { success: false, error: 'ct1 and ct2 hex ciphertexts are required' },
          { status: 400 }
        );
      }
      const result = dragXorCrib(ct1, ct2, crib);
      return NextResponse.json({ success: true, tool, crib, ...result });
    }

    if (tool === 'rsa_factor') {
      const { n, e = 65537, method = 'all' } = body;
      if (!n) {
        return NextResponse.json(
          { success: false, error: 'Modulus n is required for RSA factor analysis' },
          { status: 400 }
        );
      }
      const result = rsaWeakPrimes({ n, e, method });
      return NextResponse.json({ success: true, tool, ...result });
    }

    return NextResponse.json(
      { success: false, error: `Unknown CTF solver tool: '${tool}'` },
      { status: 400 }
    );
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
