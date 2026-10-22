import { NextRequest, NextResponse } from 'next/server';
import { listSavedXmlScans, readXmlScan, parseNmapXml } from 'vigilante_lib/engine/nmap-xml.js';
import { saveEvidenceFile } from 'vigilante_lib/engine/evidence.js';
import { authorizeRequest } from '@/lib/authz';
import { errorMessage } from '@/lib/envelope';

export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const denied = await authorizeRequest(req, 'scans:read');
  if (denied) return denied;

  try {
    const { searchParams } = new URL(req.url);
    const id = searchParams.get('id');

    const scans = await listSavedXmlScans();

    if (id) {
      const target = scans.find(s => s.id === id || s.filename === id || s.filePath === id);
      if (target) {
        const fullScan = await readXmlScan(target.filePath);
        return NextResponse.json({ success: true, scan: fullScan });
      }
      return NextResponse.json({ success: false, error: 'Scan not found' }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      scansCount: scans.length,
      scans
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  const denied = await authorizeRequest(req, 'scans:run');
  if (denied) return denied;

  try {
    const body = await req.json();

    const xmlContent = body.xmlContent;
    const target = body.target || 'uploaded_scan';

    if (!xmlContent) {
      return NextResponse.json({ success: false, error: 'xmlContent is required' }, { status: 400 });
    }

    const parsed = parseNmapXml(xmlContent);
    const filename = `scan-${Date.now()}.xml`;
    await saveEvidenceFile(target, 'scanner', filename, xmlContent);

    return NextResponse.json({
      success: true,
      scan: parsed,
      filename
    });
  } catch (err: unknown) {
    return NextResponse.json({ success: false, error: errorMessage(err) }, { status: 500 });
  }
}
