import { NextRequest, NextResponse } from 'next/server';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  generateDeBruijnPattern,
  findDeBruijnOffset,
  autoIdentifyCipher,
  parseJwt,
  dragXorCrib,
  rsaWeakPrimes,
  findRopGadgets,
  checksec
} from 'vigilante_lib/engine/ctf-tools.js';
import { resolvePathInside } from 'vigilante_lib/engine/config.js';
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
      const result = (rsaWeakPrimes as any)({ n, e, method });
      return NextResponse.json({ success: true, tool, ...result });
    }

    if (tool === 'rop') {
      let buf: Buffer | null = null;
      if (body.hexBytes) {
        buf = Buffer.from(body.hexBytes.replace(/[^0-9a-fA-F]/g, ''), 'hex');
      } else if (body.base64Bytes) {
        buf = Buffer.from(body.base64Bytes, 'base64');
      } else if (body.filePath) {
        const allowedBase = path.resolve(process.cwd(), 'ctf-workspace');
        let targetPath: string;
        try {
          targetPath = resolvePathInside(allowedBase, String(body.filePath));
        } catch {
          return NextResponse.json(
            { success: false, error: 'Path traversal: filePath must reside within ctf-workspace' },
            { status: 400 }
          );
        }
        buf = await fs.readFile(targetPath);
      }

      if (!buf || buf.length === 0) {
        return NextResponse.json(
          { success: false, error: 'Binary input required: provide hexBytes, base64Bytes, or a filePath within ctf-workspace' },
          { status: 400 }
        );
      }

      const ropResult = (findRopGadgets as any)({ binaryBuffer: buf });
      return NextResponse.json({ success: true, tool, ...ropResult });
    }

    if (tool === 'checksec') {
      let buf: Buffer | null = null;
      if (body.hexBytes) {
        buf = Buffer.from(body.hexBytes.replace(/[^0-9a-fA-F]/g, ''), 'hex');
      } else if (body.base64Bytes) {
        buf = Buffer.from(body.base64Bytes, 'base64');
      } else if (body.filePath) {
        const allowedBase = path.resolve(process.cwd(), 'ctf-workspace');
        let targetPath: string;
        try {
          targetPath = resolvePathInside(allowedBase, String(body.filePath));
        } catch {
          return NextResponse.json(
            { success: false, error: 'Path traversal: filePath must reside within ctf-workspace' },
            { status: 400 }
          );
        }
        buf = await fs.readFile(targetPath);
      }

      if (!buf || buf.length === 0) {
        return NextResponse.json(
          { success: false, error: 'Binary input required: provide hexBytes, base64Bytes, or a filePath within ctf-workspace' },
          { status: 400 }
        );
      }

      const secInfo = await checksec(buf);
      return NextResponse.json({ success: true, tool, ...secInfo });
    }

    return NextResponse.json(
      { success: false, error: `Unknown CTF solver tool: '${tool}'` },
      { status: 400 }
    );
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
