import { NextResponse } from 'next/server';
import { FalcoModule } from 'vigilante_lib/modules/falco/index.js';
import { loadConfig } from 'vigilante_lib/engine/config.js';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const config = loadConfig();
    const clusterName = config.defaults?.clusterName || 'vigilante-dev';
    const domain = config.defaults?.domain || 'vigilante.local';

    const falcoMod = new FalcoModule();
    const status = await falcoMod.status({ domain, clusterName });
    const driver = falcoMod.getDriverInfo();

    return NextResponse.json({
      success: true,
      clusterName,
      domain,
      status,
      driver
    });
  } catch (err: any) {
    return NextResponse.json({
      success: false,
      error: err.message
    }, { status: 500 });
  }
}
