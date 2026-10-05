import { NextRequest, NextResponse } from 'next/server';
import { listSavedXmlScans, readXmlScan, compareNmapScans } from 'vigilante_lib/engine/nmap-xml.js';

export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest) {
  try {
    const { baseId, targetId } = await req.json();

    const scans = await listSavedXmlScans();
    const baseMeta = scans.find(s => s.id === baseId || s.filename === baseId || s.filePath === baseId);
    const targetMeta = scans.find(s => s.id === targetId || s.filename === targetId || s.filePath === targetId);

    if (!baseMeta || !targetMeta) {
      return NextResponse.json({ success: false, error: 'Both baseId and targetId must be valid scans' }, { status: 400 });
    }

    const baseScan = await readXmlScan(baseMeta.filePath);
    const targetScan = await readXmlScan(targetMeta.filePath);

    const diff = compareNmapScans(baseScan, targetScan);

    return NextResponse.json({
      success: true,
      baseScan: { id: baseMeta.id, filename: baseMeta.filename, target: baseScan.target },
      targetScan: { id: targetMeta.id, filename: targetMeta.filename, target: targetScan.target },
      diff
    });
  } catch (err: any) {
    return NextResponse.json({ success: false, error: err.message }, { status: 500 });
  }
}
