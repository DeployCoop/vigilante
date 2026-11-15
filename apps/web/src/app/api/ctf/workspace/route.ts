import { NextRequest, NextResponse } from 'next/server';
import {
  initCtfWorkspace,
  generateSignedWriteup,
  sealSolveEvidence
} from 'vigilante_lib/engine/ctf-client.js';
import { CHALLENGE_TEMPLATES } from 'vigilante_lib/engine/kctf.js';
import { resolvePathInside } from 'vigilante_lib/engine/config.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'ctf:read');
  if (denied) return denied;

  try {
    const body = await req.json().catch(() => ({}));
    const action = body.action || 'init';
    const baseDir = process.cwd();

    if (action === 'init') {
      const {
        targetDir = './ctf-workspace',
        tournamentTitle = 'Vigilante Cyber Range Tournament',
        tournamentUrl = 'https://ctf.vigilante.local',
        teamToken = null,
        teamName = 'Team Unknown'
      } = body;

      let safeTargetDir: string;
      try {
        safeTargetDir = resolvePathInside(baseDir, String(targetDir));
      } catch {
        return NextResponse.json(
          { success: false, error: 'Path traversal: targetDir must reside within workspace root' },
          { status: 400 }
        );
      }

      const result = await initCtfWorkspace({
        targetDir: safeTargetDir,
        tournamentTitle,
        tournamentUrl,
        teamToken,
        teamName,
        challenges: CHALLENGE_TEMPLATES
      });

      return NextResponse.json({
        success: true,
        action: 'init',
        ...result
      });
    }

    if (action === 'writeup') {
      const {
        challengeId,
        challengeName,
        category,
        author,
        teamName,
        vulnerabilityDescription,
        exploitScript,
        flag,
        outputDir
      } = body;

      if (!challengeId) {
        return NextResponse.json(
          { success: false, error: 'challengeId is required for writeup generation' },
          { status: 400 }
        );
      }

      let safeOutputDir = outputDir;
      if (outputDir) {
        try {
          safeOutputDir = resolvePathInside(baseDir, String(outputDir));
        } catch {
          return NextResponse.json(
            { success: false, error: 'Path traversal: outputDir must reside within workspace root' },
            { status: 400 }
          );
        }
      }

      const result = await generateSignedWriteup({
        challengeId,
        challengeName,
        category,
        author,
        teamName,
        vulnerabilityDescription,
        exploitScript,
        flag,
        outputDir: safeOutputDir
      });

      return NextResponse.json({
        success: true,
        action: 'writeup',
        ...result
      });
    }

    if (action === 'seal') {
      const {
        teamId = 'web-player',
        challengeId,
        flag,
        solveScriptContent,
        writeupContent,
        sessionCastContent,
        outputDir
      } = body;

      if (!challengeId || !flag) {
        return NextResponse.json(
          { success: false, error: 'challengeId and flag are required to seal evidence' },
          { status: 400 }
        );
      }

      let safeOutputDir = outputDir;
      if (outputDir) {
        try {
          safeOutputDir = resolvePathInside(baseDir, String(outputDir));
        } catch {
          return NextResponse.json(
            { success: false, error: 'Path traversal: outputDir must reside within workspace root' },
            { status: 400 }
          );
        }
      }

      const result = await (sealSolveEvidence as any)({
        teamId,
        challengeId,
        flag,
        solveScriptContent,
        writeupContent,
        sessionCastContent,
        outputDir: safeOutputDir
      });

      return NextResponse.json({
        success: true,
        action: 'seal',
        ...result
      });
    }

    return NextResponse.json(
      { success: false, error: `Unsupported workspace action: '${action}'` },
      { status: 400 }
    );
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
