import { NextResponse } from 'next/server';
import { runPipelineAudit, generateSarifReport } from 'vigilante_lib/engine/audit.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(request: Request) {
  const denied = await authorizeRequest(request, 'scans:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(request.url);
    const targetPath = searchParams.get('path') || '.';
    const sarif = searchParams.get('sarif') === 'true';

    const result = await runPipelineAudit(targetPath, { failOn: 'HIGH' });

    if (sarif) {
      const sarifReport = generateSarifReport(result.findings);
      return NextResponse.json(sarifReport);
    }

    return NextResponse.json({
      success: true,
      result
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        success: false,
        error: errorMessage(err),
        findings: []
      },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  const denied = await authorizeRequest(request, 'scans:run');
  if (denied) return denied;

  try {
    const body = await request.json();

    const { targetPath = '.', failOn = 'HIGH' } = body;

    const result = await runPipelineAudit(targetPath, { failOn });
    const sarif = generateSarifReport(result.findings);

    return NextResponse.json({
      success: true,
      result,
      sarif
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
